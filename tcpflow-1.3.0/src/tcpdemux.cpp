/*
 * This file is part of tcpflow by Simson Garfinkel,
 * originally by Jeremy Elson <jelson@circlemud.org>
 *
 * This source code is under the GNU Public License (GPL).  See
 * LICENSE for details.
 *
 */

#include "tcpflow.h"

#include <iostream>
#include <sstream>

extern char * g_pc_vnc_file_name;

/**
 * Close all of the flows in the fd_ring
 */
void tcpdemux::close_all()
{
    for(tcpset::iterator it = openflows.begin();it!=openflows.end();it++){
	(*it)->close_file();
	(*it)->close_vnc_file();
    }
    openflows.clear();
}


void tcpdemux::close_tcpip(tcpip *i)
{
    i->close_file();
	i->close_vnc_file();
    openflows.erase(i);
}

/**
 * find the flow that has been written to in the furthest past and close it.
 */
void tcpdemux::close_oldest()
{
    tcpip *oldest_tcp=0;
    for(tcpset::iterator it = openflows.begin();it!=openflows.end();it++){
	if(oldest_tcp==0 || (*it)->last_packet_time < oldest_tcp->last_packet_time){
	    oldest_tcp = (*it);
	}
    }
    if(oldest_tcp) close_tcpip(oldest_tcp);
	if(oldest_tcp) oldest_tcp->close_vnc_file();
}

/* Find previously a previously created flow state in the database.
 */
tcpip *tcpdemux::find_tcpip(const flow_addr &flow)
{
    flow_map_t::const_iterator it = flow_map.find(flow);
    if (it==flow_map.end()){
	return NULL; // flow not found
    }
    return it->second;
}

/* Create a new flow state structure for a given flow.
 * Puts the flow in the map.
 * Returns a pointer to the new state.
 * Do we really want to keep pointers to tcp structures in the map, rather than
 * the structures themselves?
 */

tcpip *tcpdemux::create_tcpip(const flow_addr &flowa, int32_t vlan,tcp_seq isn,
			      const timeval &ts,uint64_t connection_count)
{
    /* create space for the new state */
    flow flow(flowa,vlan,ts,ts,flow_counter++,connection_count);

    tcpip *new_tcpip = new tcpip(*this,flow,isn);
    new_tcpip->last_packet_time = packet_time++;
    DEBUG(5) ("%s: new flow", new_tcpip->flow_pathname.c_str());
    flow_map[flow] = new_tcpip;
    return new_tcpip;
}

void tcpdemux::remove_flow(const flow_addr &flow)
{
    flow_map_t::iterator it = flow_map.find(flow);
    if(it!=flow_map.end()){
	close_tcpip(it->second);
	delete it->second;
	flow_map.erase(it);
    }
}

void tcpdemux::flow_map_clear()
{
    for(flow_map_t::iterator it=flow_map.begin();it!=flow_map.end();it++){
	delete it->second;
    }
    flow_map.clear();
}

int tcpdemux::open_tcpfile(tcpip *tcp)
{
    /* This shouldn't be called if the file is already open */
    if (tcp->fp) {
	DEBUG(20) ("huh -- trying to open already open file!");
	return 0;
    }

    /* Now try and open the file */
    if(tcp->file_created) {
	DEBUG(5) ("%s: re-opening output file", tcp->flow_pathname.c_str());
	tcp->fp = retrying_fopen(tcp->flow_pathname.c_str(),"r+b");
    } else {
	DEBUG(5) ("%s: opening new output file", tcp->flow_pathname.c_str());
	tcp->fp = retrying_fopen(tcp->flow_pathname.c_str(),"wb");
    }

    /* If the file isn't open at this point, there's a problem */
    if (tcp->fp == NULL) {
	/* we had some problem opening the file -- set FINISHED so we
	 * don't keep trying over and over again to reopen it
	 */
	perror(tcp->flow_pathname.c_str());
	return -1;
    }

    openflows.insert(tcp);
    tcp->file_created = true;		// remember we made it
    tcp->pos = ftell(tcp->fp);		// remember where it is
    return 0;
}

int tcpdemux::open_vnc_file(tcpip *tcp)
{
	if (tcp->vnc_fd < 0){
		tcp->vnc_fd = open(g_pc_vnc_file_name, O_RDWR|O_BINARY|O_CREAT, 0666);
		if (tcp->vnc_fd < 0){
			perror("/var/log/vnc_log");
			return -1;
		}
	}

	return 0;
}


/****************************************************************
 *** tcpdemultiplexer 
 ****************************************************************/

/* Try to find the maximum number of FDs this system can have open */
unsigned int tcpdemux::get_max_fds(void)
{
    int max_descs = 0;
    const char *method;

    /* Use OPEN_MAX if it is available */
#if defined (OPEN_MAX)
    method = "OPEN_MAX";
    max_descs = OPEN_MAX;
#elif defined(RLIMIT_NOFILE)
    {
	struct rlimit limit;
	memset(&limit,0,sizeof(limit));

	method = "rlimit";
	if (getrlimit(RLIMIT_NOFILE, &limit) < 0) {
	    perror("getrlimit");
	    exit(1);
	}

	/* set the current to the maximum or specified value */
	if (max_desired_fds) limit.rlim_cur = max_desired_fds;
	else limit.rlim_cur = limit.rlim_max;

	if (setrlimit(RLIMIT_NOFILE, &limit) < 0) {
	    perror("setrlimit");
	    exit(1);
	}
	max_descs = limit.rlim_max;

#ifdef RLIM_INFINITY
	if (limit.rlim_max == RLIM_INFINITY) max_descs = MAX_FD_GUESS * 4;	/* pick a more reasonable max */
#endif
    }
#elif defined (_SC_OPEN_MAX)
    /* Okay, you don't have getrlimit() and you don't have OPEN_MAX.
     * Time to try the POSIX sysconf() function.  (See Stevens'
     * _Advanced Programming in the UNIX Environment_).  */
    method = "POSIX sysconf";
    errno = 0;
    if ((max_descs = sysconf(_SC_OPEN_MAX)) < 0) {
	if (errno == 0)
	    max_descs = MAX_FD_GUESS * 4;
	else {
	    perror("calling sysconf");
	    exit(1);
	}
    }

    /* if everything has failed, we'll just take a guess */
#else
    method = "random guess";
    max_descs = MAX_FD_GUESS;
#endif

    /* this must go here, after rlimit code */
    if (max_desired_fds) {
	DEBUG(10) ("using only %d FDs", max_desired_fds);
	return max_desired_fds;
    }

    DEBUG(10) ("found max FDs to be %d using %s", max_descs, method);
    return max_descs;
}


tcpdemux::tcpdemux():outdir("."),flow_counter(0),packet_time(0),
		     xreport(0),max_fds(10),flow_map(),
		     start_new_connections(false),
		     openflows(),
		     opt_output_enabled(true),opt_md5(false),
		     opt_after_header(false),opt_gzip_decompress(true),
		     opt_no_promisc(false),
		     max_bytes_per_flow(),max_desired_fds()
{
    /* Find out how many files we can have open safely...subtract 4 for
     * stdin, stdout, stderr, and the packet filter; one for breathing
     * room (we open new files before closing old ones), and one more to
     * be safe.
     */
    max_fds = get_max_fds() - NUM_RESERVED_FDS;
}


/* write a portion of memory to the disk. */
void tcpdemux::write_to_file(std::stringstream &ss,
			  const std::string &fname,const uint8_t *base,const uint8_t *buf,size_t buflen)
{
    int fd = retrying_open(fname.c_str(),O_WRONLY|O_CREAT|O_BINARY|O_TRUNC,0644);
    if(fd>=0){
	size_t count = write(fd,buf,buflen);
	if(close(fd)!=0 || count!=buflen){
	    std::cerr << "cannot write " << fname << ": " << strerror(errno) << "\n";
	    ss << "<write_error errno='" << errno << "' buflen='" << buflen << "' count='" << count << "'>";
	} else {
	    ss << "<byte_run file_offset='" << buf-base << "' len='" << buflen << "'>";
	    ss << "<filename>" << fname << "</filename>";
	    ss << "<hashdigest type='MD5'>" << md5_generator::hash_buf(buf,buflen).hexdigest() << "</hashdigest>";
	    ss << "</byte_run>\n";
	}
    }
}

/* Open a file, shriking the ring if necessary */
int tcpdemux::retrying_open(const char *filename,int oflag,int mask)
{
    while(true){
	if(openflows.size() >= max_fds) close_oldest();
	int fd = ::open(filename,oflag,mask);
	DEBUG(2)("::open(%s,%d,%d)=%d",filename,oflag,mask,fd);
	if(fd>=0) return fd;
	DEBUG(2)("retrying_open ::open failed with errno=%d",errno);
	if (errno != ENFILE && errno != EMFILE){
	    DEBUG(2)("retrying_open ::open failed with errno=%d (%s)",errno,strerror(errno));
	    return -1;		// wonder what it was
	}
	DEBUG(5) ("too many open files -- contracting FD ring to %d", max_fds);
	close_oldest();
    }
}

FILE *tcpdemux::retrying_fopen(const char *filename,const char *mode)
{
    while(true){
	if(openflows.size() >= max_fds) close_oldest();
	FILE *f = fopen(filename,mode);
	if(f) return f;
	
	if (errno != ENFILE && errno != EMFILE) {
	    return 0;
	}
	/* open failed because too many files are open... close one
	 * and try again
	 */
	close_oldest();
	DEBUG(5) ("too many open files -- contracting FD ring to %d", max_fds);
    };
}

/* convert all non-printable characters to '.' (period).  
 */
static u_char *do_strip_nonprint(const u_char *data, u_char *buf,uint32_t length)
{
    u_char *write_ptr = buf;
    while (length) {
	if (isprint(*data) || (*data == '\n') || (*data == '\r'))
	    *write_ptr = *data;
	else
	    *write_ptr = '.';
	write_ptr++;
	data++;
	length--;
    }
    return buf;
}

/*
 * Called to processes a tcp packet
 */

void tcpdemux::process_tcp(const struct timeval *ts,const u_char *data, uint32_t length,
			const ipaddr &src, const ipaddr &dst,int32_t vlan,sa_family_t family)
{
    struct tcphdr *tcp_header = (struct tcphdr *) data;
    u_int tcp_header_len;
    tcp_seq seq;

    if (length < sizeof(struct tcphdr)) {
	DEBUG(6) ("received truncated TCP segment!");
	return;
    }

    /* calculate the total length of the TCP header including options */
    tcp_header_len = tcp_header->th_off * 4;

    /* fill in the flow_addr structure with info that identifies this flow */
    flow_addr this_flow(src,dst,ntohs(tcp_header->th_sport),ntohs(tcp_header->th_dport),family);

    seq = ntohl(tcp_header->th_seq);
    int syn_set = IS_SET(tcp_header->th_flags, TH_SYN);
    /* recalculate the beginning of data and its length, moving past the
     * TCP header
     */
    data   += tcp_header_len;
    length -= tcp_header_len;

    /* see if we have state about this flow; if not, create it */
    tcpip *tcp = find_tcpip(this_flow);
    
    if(tcp==0 && start_new_connections==false) return; // don't start new ones

    uint64_t connection_count = 0;
    if(tcp){
	/* If offset will be too much, throw away this_flow and create a new one */
	tcp_seq isn2 = tcp->isn;		// local copy
	if(syn_set){
	    isn2 = seq - tcp->pos + 1;
	}
	tcp_seq offset  = seq - isn2;	// offset from the last seen packet to beginning of current
	tcp_seq roffset = isn2 - seq;
	if(offset != tcp->pos) {
            /** We need to seek if offset doesn't match current position.
	     * If the seek is too much, start a new connection.
	     * roffset handles reverse seek, which happens with out-of-order packet delivery.
	     */
	    if((offset > tcp->pos)
	       && (offset > tcp->pos_max)
	       && (length > 0)
	       && (max_bytes_per_flow==0) 
	       && ((uint64_t)offset > (uint64_t)tcp->pos +  min_skip)
	       && (roffset > min_skip)){
		//std::cerr << "tcp->pos=" << tcp->pos << " tcp->pos_max="
		//<< tcp->pos_max << " offset=" << offset << " min_skip="
		//<< min_skip << "  this_flow=" << this_flow << "\n";
		connection_count = tcp->myflow.connection_count+1;
		remove_flow(this_flow);
		tcp = 0;
	    }
	}
    }
    if (tcp==NULL){
	tcp = create_tcpip(this_flow, vlan, seq, *ts,connection_count);
    } else {
	tcp->myflow.tlast = *ts;		// most recently seen packet
    }

    tcp->myflow.packet_count++;

    /* Handle empty packets (from Debian patch 10) */
    if (length == 0) {
	/* examine TCP flags for initial TCP handshake segments:
	 * - SYN means that the flow is a client -> server flow
	 * - SYN/ACK means that the flow is a server -> client flow.
	 */
	if ((tcp->isn - seq) == 0) {
	    if (IS_SET(tcp_header->th_flags, TH_SYN) && IS_SET(tcp_header->th_flags, TH_ACK)) {
		tcp->dir = tcpip::dir_sc;
		DEBUG(50) ("packet is handshake SYN/ACK");
		/* If the SYN flag is set the first data byte is offset by one,
		 * account for it (note: if we're here we have just created
		 * tcp, so it's safe to change isn).
		 */
		tcp->isn++;
	    } else if (IS_SET(tcp_header->th_flags, TH_SYN)) {
		tcp->dir = tcpip::dir_cs;
		DEBUG(50) ("packet is handshake SYN");
		tcp->isn++;
	    }
	}
	DEBUG(50) ("got TCP segment with no data");
    }

    if (length>0){
	/* strip nonprintable characters if necessary */
	u_char newbuf[SNAPLEN];
	if (strip_nonprint){
	    data = do_strip_nonprint(data, newbuf,length);
	}
	
	/* store or print the output */
	if (console_only) {
	    tcp->print_packet(data, length);
	} else {
		if (!dont_store_file){
		    tcp->store_packet(data, length, seq, syn_set);
		}
		if (my_handle_output){
			tcp->handle_packet(data, length);
		}
	}
    }

    /* Finally, if there is a FIN, then kill this TCP connection*/
    if (IS_SET(tcp_header->th_flags, TH_FIN)){
	if(opt_no_purge==false){
	    DEBUG(50)("packet is FIN; closing connection");
	    remove_flow(this_flow);	// take it out of the map
	}
    }
}



/* This is called when we receive an IPv4 datagram.  We make sure that
 * it's valid and contains a TCP segment; if so, we pass it to
 * process_tcp() for further processing.
 *
 * Note: we currently don't know how to handle IP fragments. */
void tcpdemux::process_ip4(const struct timeval *ts,const u_char *data, uint32_t caplen,int32_t vlan)
{
    const struct ip *ip_header = (struct ip *) data;
    u_int ip_header_len;
    u_int ip_total_len;

    /* make sure that the packet is at least as long as the min IP header */
    if (caplen < sizeof(struct ip)) {
	DEBUG(6) ("received truncated IP datagram!");
	return;
    }

    DEBUG(100)("process_ip4. caplen=%d vlan=%d  ip_p=%d",(int)caplen,(int)vlan,(int)ip_header->ip_p);

    /* for now we're only looking for TCP; throw away everything else */
    if (ip_header->ip_p != IPPROTO_TCP) {
	DEBUG(50) ("got non-TCP frame -- IP proto %d", ip_header->ip_p);
	return;
    }

    /* check and see if we got everything.  NOTE: we must use
     * ip_total_len after this, because we may have captured bytes
     * beyond the end of the packet (e.g. ethernet padding).
     */
    ip_total_len = ntohs(ip_header->ip_len);
    if (caplen < ip_total_len) {
	DEBUG(6) ("warning: captured only %ld bytes of %ld-byte IP datagram",
		  (long) caplen, (long) ip_total_len);
    }

    /* XXX - throw away everything but fragment 0; this version doesn't
     * know how to do fragment reassembly.
     */
    if (ntohs(ip_header->ip_off) & 0x1fff) {
	DEBUG(2) ("warning: throwing away IP fragment from X to X");
	return;
    }

    /* figure out where the IP header ends */
    ip_header_len = ip_header->ip_hl * 4;

    /* make sure there's some data */
    if (ip_header_len > ip_total_len) {
	DEBUG(6) ("received truncated IP datagram!");
	return;
    }

    /* do TCP processing, faking an ipv6 address  */
    process_tcp(ts,data + ip_header_len, ip_total_len - ip_header_len,
		ipaddr(ip_header->ip_src.s_addr),
		ipaddr(ip_header->ip_dst.s_addr),
		vlan,AF_INET);
}


/* This is called when we receive an IPv6 datagram.
 *
 * Note: we don't support IPv6 extended headers
 */

struct private_ip6_hdr {
	union {
		struct ip6_hdrctl {
			uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			uint16_t ip6_un1_plen;	/* payload length */
			uint8_t  ip6_un1_nxt;	/* next header */
			uint8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		uint8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	struct private_in6_addr ip6_src;	/* source address */
	struct private_in6_addr ip6_dst;	/* destination address */
} __attribute__((__packed__));

/* These might be defined from an include file, so undef them to be sure */
#undef ip6_vfc
#undef ip6_flow
#undef ip6_plen	
#undef ip6_nxt	
#undef ip6_hlim	
#undef ip6_hops	

#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim



void tcpdemux::process_ip6(const struct timeval *ts,const u_char *data, const uint32_t caplen, const int32_t vlan)
{
    const struct private_ip6_hdr *ip_header = (struct private_ip6_hdr *) data;
    u_int16_t ip_payload_len;

    /* make sure that the packet is at least as long as the IPv6 header */
    if (caplen < sizeof(struct private_ip6_hdr)) {
	DEBUG(6) ("received truncated IPv6 datagram!");
	return;
    }


    /* for now we're only looking for TCP; throw away everything else */
    if (ip_header->ip6_nxt != IPPROTO_TCP) {
	DEBUG(50) ("got non-TCP frame -- IP proto %d", ip_header->ip6_nxt);
	return;
    }

    ip_payload_len = ntohs(ip_header->ip6_plen);

    /* make sure there's some data */
    if (ip_payload_len == 0) {
	DEBUG(6) ("received truncated IP datagram!");
	return;
    }

    /* do TCP processing */

    process_tcp(ts,
		data + sizeof(struct private_ip6_hdr),
		ip_payload_len,
		ipaddr(ip_header->ip6_src.s6_addr),
		ipaddr(ip_header->ip6_dst.s6_addr),
		vlan,AF_INET6);
}



/* This is called when we receive an IPv4 or IPv6 datagram.
 * This function calls process_ip4 or process_ip6
 */

void tcpdemux::process_ip(const struct timeval *ts,const u_char *data, uint32_t caplen,int32_t vlan)
{
    const struct ip *ip_header = (struct ip *) data;
    if (caplen < sizeof(struct ip)) {
	DEBUG(6) ("can't determine IP datagram version!");
	return;
    }

    if(ip_header->ip_v == 6) {
	process_ip6(ts,data, caplen,vlan);
    } else {
	process_ip4(ts,data, caplen,vlan);
    }
}
 
 
/* This has to go somewhere; might as well be here */
static void terminate(int sig) __attribute__ ((__noreturn__));
static void terminate(int sig)
{
    DEBUG(1) ("terminating");
    exit(0); /* libpcap uses onexit to clean up */
}



/*
 * process an input file or device
 * May be repeated.
 * If start is false, do not initiate new connections
 */
void tcpdemux::process_infile(const std::string &expression,const char *device,const std::string &infile,bool start)
{
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *pd=0;
    int dlt=0;
    pcap_handler handler;

    start_new_connections = start;
    if (infile!=""){
	if ((pd = pcap_open_offline(infile.c_str(), error)) == NULL){	/* open the capture file */
	    die("%s", error);
	}

	dlt = pcap_datalink(pd);	/* get the handler for this kind of packets */
	handler = find_handler(dlt, infile.c_str());
    } else {
	/* if the user didn't specify a device, try to find a reasonable one */
	if (device == NULL){
	    if ((device = pcap_lookupdev(error)) == NULL){
		die("%s", error);
	    }
	}

	/* make sure we can open the device */
	if ((pd = pcap_open_live(device, SNAPLEN, !opt_no_promisc, 1000, error)) == NULL){
	    die("%s", error);
	}
#if defined(HAVE_SETUID) && defined(HAVE_GETUID)
	/* drop root privileges - we don't need them any more */
	setuid(getuid());
#endif
	/* get the handler for this kind of packets */
	dlt = pcap_datalink(pd);
	handler = find_handler(dlt, device);
    }

    /* If DLT_NULL is "broken", giving *any* expression to the pcap
     * library when we are using a device of type DLT_NULL causes no
     * packets to be delivered.  In this case, we use no expression, and
     * print a warning message if there is a user-specified expression
     */
#ifdef DLT_NULL_BROKEN
    if (dlt == DLT_NULL && expression != ""){
	DEBUG(1)("warning: DLT_NULL (loopback device) is broken on your system;");
	DEBUG(1)("         filtering does not work.  Recording *all* packets.");
    }
#endif /* DLT_NULL_BROKEN */

    DEBUG(20) ("filter expression: '%s'",expression.c_str());

    /* install the filter expression in libpcap */
    struct bpf_program	fcode;
    if (pcap_compile(pd, &fcode, expression.c_str(), 1, 0) < 0){
	die("%s", pcap_geterr(pd));
    }

    if (pcap_setfilter(pd, &fcode) < 0){
	die("%s", pcap_geterr(pd));
    }

    /* initialize our flow state structures */

    /* set up signal handlers for graceful exit (pcap uses onexit to put
     * interface back into non-promiscuous mode
     */
    portable_signal(SIGTERM, terminate);
    portable_signal(SIGINT, terminate);
#ifdef SIGHUP
    portable_signal(SIGHUP, terminate);
#endif

    /* start listening! */
    if (infile == "") DEBUG(1) ("listening on %s", device);
    if (pcap_loop(pd, -1, handler, (u_char *)this) < 0){
	die("%s", pcap_geterr(pd));
    }
}

