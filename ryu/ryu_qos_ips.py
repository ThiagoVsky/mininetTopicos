from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp

class QoS_IPS_Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(QoS_IPS_Controller, self).__init__(*args, **kwargs)
        self.logger.info("QoS + IPS Controller iniciado!")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Configuração inicial do switch"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Regra padrão: envia pacotes desconhecidos ao controlador
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Bloquear tráfego entre s3 (dpid=3) e s2 (dpid=2)
        if dpid == 3:
            match = parser.OFPMatch()
            actions = []  # Bloquear todo o tráfego
            self.add_flow(datapath, 100, match, actions)
            self.logger.warning("🚫 Todo tráfego do s3 bloqueado para s2!")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Intercepta pacotes para aplicar bloqueios"""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        dns_pkt = pkt.get_protocol(dns.dns)

        if ip and dpid == 2:  # Se for o switch s2
            if ip.dst in self.blocked_ips_s2:
                self.logger.warning(f"⚠️ Bloqueando tráfego de {ip.src} para {ip.dst} no s2")
                match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip.dst)
                self.add_flow(datapath, 100, match, [])
                return

        # Captura DNS para bloquear Google e YouTube em s2
        if dns_pkt and dpid == 2:
            self.inspect_dns(pkt, datapath)

        if not ip:
            return  # Ignora pacotes que não são IPv4

        # 🔴 IPS: Bloquear tráfego para Telnet (porta 23)
        if tcp_pkt and tcp_pkt.dst_port == 23:
            self.logger.warning("⚠️ Tráfego Telnet detectado! Bloqueando...")
            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip.dst, ip_proto=6, tcp_dst=23)
            self.add_flow(datapath, 100, match, [])  # Bloqueia pacotes
            return

    def inspect_dns(self, pkt, datapath):
        """ Captura respostas DNS para identificar IPs de Google e YouTube no s2 """
        dns_pkt = pkt.get_protocol(dns.dns)
        if not dns_pkt.qr:  # Apenas processa respostas
            return

        for answer in dns_pkt.answers:
            domain = answer.name.decode() if isinstance(answer.name, bytes) else answer.name
            ip_address = answer.address

            if "google.com" in domain or "youtube.com" in domain:
                self.blocked_ips_s2.add(ip_address)
                self.logger.info(f"🚫 Bloqueando {ip_address} em s2 (Google/YouTube)")

    def add_flow(self, datapath, priority, match, actions):
        """ Adiciona regras de fluxo ao switch """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)