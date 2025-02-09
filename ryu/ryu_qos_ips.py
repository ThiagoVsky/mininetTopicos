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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Intercepta pacotes para aplicar regras de QoS e IPS"""
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if not ip:
            return  # Ignora pacotes que não são IPv4

        # 🔴 IPS: Bloquear tráfego para Telnet (porta 23)
        if tcp_pkt and tcp_pkt.dst_port == 23:
            self.logger.warning("⚠️ Tráfego Telnet detectado! Bloqueando...")
            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip.dst, ip_proto=6, tcp_dst=23)
            self.add_flow(datapath, 100, match, [])  # Bloqueia pacotes
            return

        # 🔵 QoS: Aplicar prioridades ao tráfego
        if tcp_pkt:
            if tcp_pkt.dst_port == 80:  # HTTP (prioridade alta)
                queue_id = 1
            elif tcp_pkt.dst_port == 22:  # SSH (prioridade média)
                queue_id = 2
            else:  # Outros tráfegos (prioridade baixa)
                queue_id = 0

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip.dst, ip_proto=6, tcp_dst=tcp_pkt.dst_port)
            actions = [parser.OFPActionSetQueue(queue_id), parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.add_flow(datapath, 10, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        """Adiciona regras de fluxo ao switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
