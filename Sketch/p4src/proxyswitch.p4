header_type ethernet_t {
	fields {
	dstAddr : 48;
	srcAddr : 48;
	etherType : 16;
	}
}

header_type ipv4_t {
	fields {
	version : 4;
	ihl : 4;
	diffserv : 8;
	totalLen : 16;
	identification : 16;
	flags : 3;
	fragOffset : 13;
	ttl : 8;
	protocol : 8;
	hdrChecksum : 16;
	srcAddr : 32;
	dstAddr: 32;
	}
} 


#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
header ethernet_t ethernet;



header ipv4_t ipv4;


field_list ipv4_checksum_list {
	ipv4.version;
	ipv4.ihl;
	ipv4.diffserv;
	ipv4.totalLen;
	ipv4.identification;
	ipv4.flags;
	ipv4.fragOffset;
	ipv4.ttl;
	ipv4.protocol;
	ipv4.srcAddr;
	ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
	input {
		ipv4_checksum_list;
	}
	algorithm : csum16;
	output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
	verify ipv4_checksum;
	update ipv4_checksum;
}

#define IP_PROT_TCP 0x06




header_type tcp_t {
	fields {
		srcPort : 16;
		dstPort : 16;
		seqNo : 32;
		ackNo : 32;
		dataOffset : 4;
        res : 4;
        flags : 3;
		ack: 1;
		psh: 1;
		rst: 1;
		syn: 1;
		fin: 1;		 
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header tcp_t tcp;



parser start {
	set_metadata(meta.in_port, standard_metadata.ingress_port);//
	return  parse_ethernet;
}
parser parse_ethernet {
	extract(ethernet);
	set_metadata(meta.eth_da,ethernet.dstAddr);
	set_metadata(meta.eth_sa,ethernet.srcAddr);
	return select(latest.etherType) {
		ETHERTYPE_IPV4 : parse_ipv4;
		default: ingress;
	}
}
parser parse_ipv4 {
	extract(ipv4);

	set_metadata(meta.ipv4_sa, ipv4.srcAddr);
	set_metadata(meta.ipv4_da, ipv4.dstAddr);
	set_metadata(meta.tcpLength, ipv4.totalLen - 20);	
	set_metadata(meta.ipv4_protocol, ipv4.protocol);


	return select(ipv4.protocol) {
		IP_PROT_TCP : parse_tcp;
		default: ingress;
	}
}

parser parse_tcp {
	extract(tcp);
	set_metadata(meta.tcp_sp, tcp.srcPort);
	set_metadata(meta.tcp_dp, tcp.dstPort);
	set_metadata(meta.tcp_ack, tcp.ack);
	set_metadata(meta.tcp_psh, tcp.psh);
	set_metadata(meta.tcp_rst, tcp.rst);
	set_metadata(meta.tcp_syn, tcp.syn);
	set_metadata(meta.tcp_fin, tcp.fin);	
	set_metadata(meta.tcp_seqNo, tcp.seqNo);
	set_metadata(meta.tcp_ackNo, tcp.ackNo);	
	return ingress;
}
field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        meta.tcpLength;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.flags;
		tcp.ack;
		tcp.psh;
		tcp.rst;
		tcp.syn;
		tcp.fin;		 
        tcp.window;
        tcp.urgentPtr;
        payload;
}
field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    verify tcp_checksum if(valid(tcp));
    update tcp_checksum if(valid(tcp));
}

header_type meta_t {
	fields {

		in_port : 8;

		eth_sa:48;
		eth_da:48;

		ipv4_sa : 32;
        ipv4_da : 32;
		ipv4_protocol: 8;

		nhop_ipv4:32;
		tcpLength: 16;

		masksa:32;
		maskda:32;
		maskprotocol:8;
		masktcpsp:16;
		masktcpdp:16;
		sketch_in:4;

		bitmap:4;
		tempsa:32;
		tempda:32;
		tempprotocol:8;
		temptcpsp:16;
		temptcpdp:16;
		
		hash1index:13;
		hash2index:13;
		hash1count:16;
		hash2count:16;


		tcp_sp : 16;
        tcp_dp : 16;
		tcp_ack:1;
		tcp_psh:1;
		tcp_rst:1;
		tcp_syn:1;
		tcp_fin:1;
		tcp_seqNo:32;
		tcp_ackNo:32;
		
	}
}

metadata meta_t meta;
field_list sketch_hash_fields {
		meta.tempsa;
		meta.tempda;
		meta.tempprotocol;
		meta.temptcpsp;
		meta.temptcpdp;
}
//get the hash according to the 5-touple of this packet
field_list_calculation sketch_h1_hash {
	input {
		sketch_hash_fields;
	}
	algorithm: crc16; //csum16
	output_width: 13;

}
field_list_calculation sketch_h2_hash {
	input {
		sketch_hash_fields;
	}
	algorithm: csum16; //csum16
	output_width: 13;

}


register sketch00{
	width:16;
	instance_count:8192;
}
register sketch01{
	width:16;
	instance_count:8192;
}
register sketch10{
	width:16;
	instance_count:8192;
}

register sketch11{
	width:16;
	instance_count:8192;
}

register debug {
	width:16;
	instance_count:10;
}
action _drop() {
	drop();
}
action _no_op()
{
	no_op();
}


table drop_table{
	actions {
		_drop;
	}
}

action bitmapInit(bitmap)
{
	modify_field(meta.bitmap, bitmap);

	//debig
	register_write(debug,1,bitmap);
}
table bitmaptable
{
	reads{
		meta.ipv4_sa : ternary;
        meta.ipv4_da : ternary;
		meta.ipv4_protocol: ternary;
		meta.tcp_sp:ternary;
		meta.tcp_dp:ternary;

	}
	actions{
		_no_op;
		bitmapInit;
	}
}
action config(sketch_cur, offset,
		masksa,
		maskda,
		maskprotocol,
		masktcpsp,
		masktcpdp)
		{
			/*
			ipv4_sa : 32;
        ipv4_da : 32;
		ipv4_protocol: 8;
		tcpLength : 16;
			*/
		// 			bitmap:4;
		// tempsa:32;
		// tempda:32;
		// tempprotocol:8;
		// temptcpsp:16;
		// temptcpdp:16;
			
			modify_field(meta.sketch_in, (meta.bitmap & sketch_cur)>>offset);
			modify_field(meta.tempsa, meta.ipv4_sa & masksa);
			modify_field(meta.tempda, meta.ipv4_da & maskda);
			modify_field(meta.tempprotocol, meta.ipv4_protocol & maskprotocol);
			modify_field(meta.temptcpsp, meta.tcp_sp & masktcpsp);
			modify_field(meta.temptcpdp, meta.tcp_dp & masktcpdp);
			// subtract_from_field(tcp.seq_no, (meta.syn_proxy_table_entry_val >> 7) & 0xffffffff);
			//debug
			register_write(debug,5,meta.bitmap);
			register_write(debug,6,sketch_cur);
			register_write(debug,7,offset);
			register_write(debug,2,(meta.bitmap & sketch_cur)>>offset);
		}
table config_table0{
	actions{
		config;
		_no_op;
	}
}
table config_table1{
	actions{
		config;
		_no_op;
	}
}

action countsketch0()
{
	modify_field_with_hash_based_offset(meta.hash1index, 0, sketch_h1_hash, 8192);
	register_read(meta.hash1count, sketch00, meta.hash1index);
	add_to_field(meta.hash1count, 1);
	register_write(sketch00, meta.hash1index, meta.hash1count);
	
	

	modify_field_with_hash_based_offset(meta.hash2index, 0, sketch_h2_hash, 8192);
	register_read(meta.hash2count, sketch01, meta.hash2index);
	add_to_field(meta.hash2count, 1);
	register_write(sketch01, meta.hash2index, meta.hash2count);

	//debug
	register_write(debug,3,meta.hash1count);
	register_write(debug,4,meta.hash2count);
	register_write(debug,8,meta.sketch_in);
	//end
}

table sketch0
{
	reads{
		meta.sketch_in:exact;
		//size   sketch_type
	}
	actions{
		countsketch0;
		_no_op;
	}
}


action set_nhop(nhop_ipv4, port) {
	modify_field(meta.nhop_ipv4, nhop_ipv4);
	modify_field(standard_metadata.egress_spec, port);
	add_to_field(ipv4.ttl, -1);
}
table ipv4_lpm_table {
	reads {
		ipv4.dstAddr : lpm;
	}
	actions {
		set_nhop;
		_drop;
	}
	size: 1024;
}




//********for forward_table********


action set_dmac(dmac) {
	modify_field(ethernet.dstAddr, dmac);
}
table forward_table {
	reads {
		meta.nhop_ipv4 : exact;
	}
	actions {
		set_dmac;
		_drop;
	}
	size: 512;
}

// action rewrite_mac(smac) {
// 	modify_field(ethernet.srcaddr, smac);
// }
// table send_frame {
// 	reads {
// 		standard_metadata.egress_port: exact;
// 	}
// 	actions {
// 		rewrite_mac;
// 		_drop;
// 	}
// 	size: 256;
// }

control ingress {
	apply(bitmaptable);
	apply(config_table0);
	apply(sketch0);
	// apply(config_table1);
	apply(ipv4_lpm_table);
	apply(forward_table);

	
	
}
control egress{
	
}
//table_add config_table1 config => 2 1 0xffff 0xffff 0x0 0x0 0x0
//table_set_default config_table1 _no_op
