package anytls

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/pires/go-proxyproto"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.AnyTLSInboundOptions](registry, C.TypeAnyTLS, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	tlsConfig                   tls.ServerConfig
	router                      adapter.ConnectionRouterEx
	logger                      logger.ContextLogger
	listener                    *listener.Listener
	service                     *anytls.Service
	proxyProtocol               bool
	proxyProtocolAcceptNoHeader bool
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter:                     inbound.NewAdapter(C.TypeAnyTLS, tag),
		router:                      uot.NewRouter(router, logger),
		logger:                      logger,
		proxyProtocol:               options.ProxyProtocol || options.ProxyProtocolAcceptNoHeader,
		proxyProtocolAcceptNoHeader: options.ProxyProtocolAcceptNoHeader,
	}

	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}

	paddingScheme := padding.DefaultPaddingScheme
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	}

	service, err := anytls.NewService(anytls.ServiceConfig{
		Users: common.Map(options.Users, func(it option.AnyTLSUser) anytls.User {
			return (anytls.User)(it)
		}),
		PaddingScheme: paddingScheme,
		Handler:       (*inboundHandler)(inbound),
		Logger:        logger,
	})
	if err != nil {
		return nil, err
	}
	inbound.service = service
	// Only AnyTLS handles these flags; other protocol listeners still reject them.
	listenOptions := options.ListenOptions
	listenOptions.ProxyProtocol = false
	listenOptions.ProxyProtocolAcceptNoHeader = false
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            listenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return common.Close(h.listener, h.tlsConfig)
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.proxyProtocol {
		policy := proxyproto.REQUIRE
		if h.proxyProtocolAcceptNoHeader {
			policy = proxyproto.USE
		}
		// Use a connection deadline: the parser treats its own timeout as no header.
		proxyConn := proxyproto.NewConn(conn, proxyproto.WithPolicy(policy), proxyproto.SetReadHeaderTimeout(0), proxyproto.ValidateHeader(validateProxyProtocolHeader))
		deadline := time.Now().Add(10 * time.Second)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		err := proxyConn.SetReadDeadline(deadline)
		if err == nil {
			_, err = proxyConn.Read(nil)
		}
		if err == nil {
			err = proxyConn.SetReadDeadline(time.Time{})
		}
		if err != nil {
			N.CloseOnHandshakeFailure(proxyConn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": PROXY protocol header"))
			return
		}
		conn = proxyConn
		metadata.Source = M.SocksaddrFromNet(proxyConn.RemoteAddr()).Unwrap()
	}
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

func validateProxyProtocolHeader(header *proxyproto.Header) error {
	if header.Command.IsLocal() {
		return nil
	}
	protocol := header.TransportProtocol
	if !protocol.IsStream() || (!protocol.IsIPv4() && !protocol.IsIPv6()) {
		return E.New("unsupported PROXY protocol transport")
	}
	if !M.SocksaddrFromNet(header.SourceAddr).Addr.IsValid() {
		return E.New("invalid PROXY protocol source address")
	}
	return nil
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
