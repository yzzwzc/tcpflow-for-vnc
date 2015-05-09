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

#define ZLIB_CONST
#ifdef GNUC_HAS_DIAGNOSTIC_PRAGMA
#  pragma GCC diagnostic ignored "-Wundef"
#  pragma GCC diagnostic ignored "-Wcast-qual"
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

extern int pid_num;

/********** RECORDING **********/

/* RFB client messages can be regarded as having two parts - a
 * constant-sized part followed by a variable-sized part.  The size of
 * the variable part depends only on the constant part.  This function
 * returns the size of a variable part, given a pointer to a constant
 * part.
 */

static size_t variable_part (char *buffer)
{
	int message = (int) *buffer;
	switch (message) {
		case 0: /* SetPixelFormat */
		case 3: /* FramebufferUpdateRequest */
		case 4: /* KeyEvent */
		case 5: /* PointerEvent */
			/* No variable part */
			return 0;
		case 1: /* FixColourMapEntries */
			{
				uint16_t number_of_colours;
				memcpy (&number_of_colours, buffer + 4, 2);
				number_of_colours = ntohs (number_of_colours);
				return number_of_colours * 6;
			}
		case 2: /* SetEncodings */
			{
				uint16_t number_of_encodings;
				memcpy (&number_of_encodings, buffer + 2, 2);
				number_of_encodings = ntohs (number_of_encodings);
				return number_of_encodings * 4;
			}
		case 6: /* ClientCutText */
			{
				uint32_t length;
				memcpy (&length, buffer + 4, 4);
				length = ntohl (length);
				return length;
			}
	} /* switch */

	/* Caught earlier anwyay */
	fprintf (stderr, "Protocol error\n");
	return 0;
}

static void double_click_option(int down, int ms_time, int x, int y)
{
	char command_buf[1024] = {0};
	static char double_flag[4] = {0};

	if (ms_time >= 200){
		memset(double_flag, 0, 4);
	}

	if (down == 1){
		if (double_flag[0] == 0){
			double_flag[0] = 1;
		} else if (double_flag[1] == 0){
			memset(double_flag, 0, 4);
			return;
		} else if (double_flag[2] == 0){
			double_flag[2] = 1;
		} else {
			memset(double_flag, 0, 4);
			return;
		}
	} else {
		if (double_flag[0] == 0){
			memset(double_flag, 0, 4);
			return;
		} else if (double_flag[1] == 0){
			double_flag[1] = 1;
		} else if (double_flag[2] == 0){
			memset(double_flag, 0, 4);
			return;
		} else {
			double_flag[3] = 1;
		}
	}

	if (double_flag[0] == 1 && double_flag[1] == 1 && double_flag[2] == 1 && double_flag[3] == 1){
	    memset(command_buf, 0, sizeof(command_buf));
	    sprintf(command_buf, "/sbin/cloudvnccommand.sh %d %d %d %d", pid_num, 0, x, y);
	    system(command_buf);
       	memset(double_flag, 0, 4);
	    return;
	}

	return;
}

/* For recording */
static int process_client_message (char *fixed, char *variable, int fd)
{
	static int first = 1;
	static char delayed_output[100];
	static int elapsed;
	static struct timeval last_tv, first_tv;
	struct timeval tv, diff;
	struct timezone tz;
	static unsigned int last_was_key_down;
	static unsigned int current_x, current_y;
	static unsigned char current_buttons;
	int ms;
	int message = (int) *fixed;
	char tmp_buf[1024] = {0};
        char command_buf[1024] = {0};

	gettimeofday (&tv, &tz);
	if (!last_tv.tv_sec && !last_tv.tv_usec)
		first_tv = last_tv = tv;
	diff.tv_sec = tv.tv_sec - last_tv.tv_sec;
	diff.tv_usec = tv.tv_usec - last_tv.tv_usec;
	ms = diff.tv_sec * 1000 + diff.tv_usec / 1000;

	if (first) {
		first = 0;
		write(fd, "RFM 001.000\nshared\n", strlen("RFM 001.000\nshared\n"));
	} else if (*delayed_output && (!last_was_key_down || message > 4)) {
		/* We need to output a deferred line after calculating
		 * the delay */
		if (ms > 0) {
			char *p = delayed_output + strlen (delayed_output);
			sprintf (p, " delay %dms", ms);
		}
		strcat (delayed_output, "\n");
		write(fd, delayed_output, strlen(delayed_output));
		last_tv = tv;
		*delayed_output = '\0';
	}

	switch (message) {
		case 0: /* SetPixelFormat */
		case 1: /* FixColourMapEntries */
		case 2: /* SetEncodings */
		case 3: /* FramebufferUpdateRequest */
			diff.tv_sec = tv.tv_sec - first_tv.tv_sec;
			diff.tv_usec = tv.tv_usec - first_tv.tv_usec;
			ms = diff.tv_sec * 1000 + diff.tv_usec / 1000;
			if (ms > (1000 * (1 + elapsed))) {
				sprintf (tmp_buf, "# At %dms from start\n", ms);
				write(fd, tmp_buf, strlen(tmp_buf));
				elapsed = ms / 1000;
			}
			return 0;
		case 4: /* KeyEvent */
			{
				char *p = delayed_output;
				const char *down_flag = "up";
				uint32_t key;

				memcpy (&key, fixed + 4, 4);
				key = ntohl (key);

				/* We might be changing key up/down into press */
				if (*delayed_output) {
					/* last_was_key_down is the last key down */
					if (fixed[1] || last_was_key_down != key || ms > 400) {
						/* Can't make a press out of that */
						char *p = delayed_output;
						p += strlen (p);
						if (ms > 0)
							sprintf (p, " delay %dms", ms);
						strcat (delayed_output, "\n");
						write(fd, delayed_output, strlen(delayed_output));
						last_tv = tv;
						*delayed_output = '\0';
						last_was_key_down = 0;
					} else {
						if (65293 == key) {
							memset(command_buf, 0, sizeof(command_buf));
							sprintf(command_buf, "/sbin/cloudvnccommand.sh %d %d", pid_num, 1);
							system(command_buf);
						}

						char *p = delayed_output;
						char *end;
						p += strcspn (p, " \t");
						p += strspn (p, " \t");
						end = p + strcspn (p, " \t");
						*end = '\0';
						end = strdup (p);
						sprintf (delayed_output, "press %s", end);
						last_was_key_down = 0;
						break;
					}
				}

				if (fixed[1]) {
					last_was_key_down = key;
					down_flag = "down";
				}
				sprintf (p, "key ");
				p += strlen (p);
				if (key < 256 && isprint ((char) key) && !isspace ((char) key))
					*p++ = (char) key;
				else {
					sprintf (p, "%#x", key);
					p += strlen (p);
				}

				sprintf (p, " %s", down_flag);
				break;
			}
		case 5: /* PointerEvent */
			{
				uint16_t x, y;
				unsigned char buttons = fixed[1];
				memcpy (&x, fixed + 2, 2);
				memcpy (&y, fixed + 4, 2);
				x = ntohs (x);
				y = ntohs (y);

				/* First deal with buttons */
				if (buttons != current_buttons) {
					int i;
					int diff = buttons ^ current_buttons;
					while ((i = ffs (diff))) {
						if (*delayed_output) {
							strcat (delayed_output, "\n");
							write(fd, delayed_output, strlen(delayed_output));
						}
						i--;
						sprintf (delayed_output,
								"button %d %s", i,
								(buttons & (1<<i)) ? "down" : "up");
						if (current_x == x && current_y == y) {
							double_click_option((buttons & (1<<i)), ms, x, y);
						}

						diff ^= 1<<i;
					}
					current_buttons = buttons;
				}

				/* Now deal with position */
				if (current_x != x || current_y != y) {
					if (*delayed_output) {
						strcat (delayed_output, "\n");
						write(fd, delayed_output, strlen(delayed_output));
					}
					sprintf (delayed_output,
							"pointer %d %d", x, y);
					current_x = x;
					current_y = y;
				}
				break;
			}
		case 6: /* ClientCutText */
			write(fd, "# ClientCutText not supported yet\n", strlen("# ClientCutText not supported yet\n"));
			break;
		default:
			fprintf (stderr, "Protocol error\n");
			return 0;
	}
	return 0;
}


tcpip::tcpip(tcpdemux &demux_,const flow &flow_,tcp_seq isn_):
    demux(demux_),myflow(flow_),isn(isn_),flow_pathname(),fp(0),pos(0),pos_min(0),pos_max(0),
    last_packet_time(0),bytes_processed(0),finished(0),vnc_fd(-1),file_created(false),dir(unknown),
    out_of_order_count(0),md5(0)
{
    /* If we are outputting the transcripts, compute the filename */
    static const std::string slash("/");
    if(demux.opt_output_enabled){
	if(demux.outdir=="."){
	    flow_pathname = myflow.filename();
	} else {
	    flow_pathname = demux.outdir + slash + myflow.filename();
	}
    }
    
    if(demux.opt_md5){			// allocate a context
	md5 = (context_md5_t *)malloc(sizeof(context_md5_t));
	if(md5){			// if we had memory, init it
	    MD5Init(md5);
	}
    }
}


#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

/* This could be much more efficient */
const char *find_crlfcrlf(const char *base,size_t len)
{
    while(len>4){
	if(base[0]=='\r' && base[1]=='\n' && base[2]=='\r' && base[3]=='\n'){
	    return base;
	}
	len--;
	base++;
    }
    return 0;
}


/**
 * fake implementation of mmap and munmap if we don't have them
 */
#if !defined(HAVE_MMAP)
#define PROT_READ 0
#define MAP_FILE 0
#define MAP_SHARED 0
void *mmap(void *addr,size_t length,int prot, int flags, int fd, off_t offset)
{
    void *buf = (void *)malloc(length);
    if(!buf) return 0;
    read(fd,buf,length);			// should explore return code
    return buf;
}

void munmap(void *buf,size_t size)
{
    free(buf);
}

#endif

/**
 * Destructor is called when flow is closed.
 * It implements "after" processing.
 */
tcpip::~tcpip()
{
    static const std::string fileobject_str("fileobject");
    static const std::string filesize_str("filesize");
    static const std::string filename_str("filename");
    static const std::string tcpflow_str("tcpflow");

    if(fp) close_file();		// close the file if it is open for some reason

    std::stringstream byte_runs;

    if(demux.opt_after_header && file_created){
	/* open the file and see if it is a HTTP header */
	int fd = demux.retrying_open(flow_pathname.c_str(),O_RDONLY|O_BINARY,0);
	if(fd<0){
	    perror("open");
	}
	else {
	    char buf[4096];
	    ssize_t len;
	    len = read(fd,buf,sizeof(buf)-1);
	    if(len>0){
		buf[len] = 0;		// be sure it is null terminated
		if(strncmp(buf,"HTTP/1.1 ",9)==0){
		    /* Looks like a HTTP response. Split it.
		     * We do this with memmap  because, quite frankly, it's easier.
		     */
		    struct stat st;
		    if(fstat(fd,&st)==0){
			void *base = mmap(0,st.st_size,PROT_READ,MAP_FILE|MAP_SHARED,fd,0);
			const char *crlf = find_crlfcrlf((const char *)base,st.st_size);
			if(crlf){
			    ssize_t head_size = crlf - (char *)base + 2;
			    demux.write_to_file(byte_runs,
					  flow_pathname+"-HTTP",
					  (const uint8_t *)base,(const uint8_t *)base,head_size);
			    if(st.st_size > head_size+4){
				size_t body_size = st.st_size - head_size - 4;
				demux.write_to_file(byte_runs,
					      flow_pathname+"-HTTPBODY",
					      (const uint8_t  *)base,(const uint8_t  *)crlf+4,body_size);
#ifdef HAVE_LIBZ
				if(demux.opt_gzip_decompress){
				    process_gzip(byte_runs,
						 flow_pathname+"-HTTPBODY-GZIP",(unsigned char *)crlf+4,body_size);
				}
#endif
			    }
			}
			munmap(base,st.st_size);
		    }
		}
	    }
	    close(fd);
	}
    }

    if(demux.xreport){
	demux.xreport->push(fileobject_str);
	if(flow_pathname.size()) demux.xreport->xmlout(filename_str,flow_pathname);
	demux.xreport->xmlout(filesize_str,pos_max);
	
	std::stringstream attrs;
	attrs << "startime='" << xml::to8601(myflow.tstart) << "' ";
	attrs << "endtime='"  << xml::to8601(myflow.tlast)  << "' ";
	attrs << "src_ipn='"  << myflow.src << "' ";
	attrs << "dst_ipn='"  << myflow.dst << "' ";
	attrs << "packets='"  << myflow.packet_count << "' ";
	attrs << "srcport='"  << myflow.sport << "' ";
	attrs << "dstport='"  << myflow.dport << "' ";
	attrs << "family='"   << (int)myflow.family << "' ";
	attrs << "out_of_order_count='" << out_of_order_count << "' ";
	
	demux.xreport->xmlout(tcpflow_str,"",attrs.str(),false);
	if(out_of_order_count==0 && md5){
	    unsigned char digest[16];
	    char hexbuf[33];
	    MD5Final(digest,md5);
	    demux.xreport->xmlout("hashdigest",
				  md5_t::makehex(hexbuf,sizeof(hexbuf),digest,sizeof(digest)),
				  "type='MD5'",false);
	    free(md5);
	}
	if(byte_runs.tellp()>0) demux.xreport->xmlout("",byte_runs.str(),"",false);
	demux.xreport->pop();
    }
}


#ifdef HAVE_LIBZ
void tcpip::process_gzip(std::stringstream &ss,
			 const std::string &fname,const unsigned char *base,size_t len)
{
    if((len>4) && (base[0]==0x1f) && (base[1]==0x8b) && (base[2]==0x08) && (base[3]==0x00)){
	size_t uncompr_size = len * 16;
	unsigned char *decompress_buf = (unsigned char *)malloc(uncompr_size);
	if(decompress_buf==0) return;	// too big?

	z_stream zs;
	memset(&zs,0,sizeof(zs));
	zs.next_in = (Bytef *)base; // note that next_in should be typedef const but is not
	zs.avail_in = len;
	zs.next_out = decompress_buf;
	zs.avail_out = uncompr_size;
		
	int r = inflateInit2(&zs,16+MAX_WBITS);
	if(r==0){
	    r = inflate(&zs,Z_SYNC_FLUSH);
	    /* Ignore the error return; process data if we got anything */
	    if(zs.total_out>0){
		demux.write_to_file(ss,fname,decompress_buf,decompress_buf,zs.total_out);
	    }
	    inflateEnd(&zs);
	}
	free(decompress_buf);
    }
}
#endif


/* Closes the file belonging to a flow, but don't take it out of the map.
 */
void tcpip::close_file()
{
    if (fp){
	struct timeval times[2];
	times[0] = myflow.tstart;
	times[1] = myflow.tstart;

	DEBUG(5) ("%s: closing file", flow_pathname.c_str());
	/* close the file and remember that it's closed */
	fflush(fp);		/* flush the file */
#if defined(HAVE_FUTIMES)
	if(futimes(fileno(fp),times)){
	    perror("futimes");
	}
#endif
#if defined(HAVE_FUTIMENS) && !defined(HAVE_FUTIMES)
	struct timespec tstimes[2];
	for(int i=0;i<2;i++){
	    tstimes[i].tv_sec = times[i].tv_sec;
	    tstimes[i].tv_nsec = times[i].tv_usec * 1000;
	}
	if(futimens(fileno(fp),tstimes)){
	    perror("futimens");
	}
#endif
	fclose(fp);
	fp = NULL;
	pos = 0;
    }
}

void tcpip::close_vnc_file()
{
	if (vnc_fd >= 0){
		close(vnc_fd);
		vnc_fd = -1;
	}
	return;
}


/*************************************************************************/

/* print the contents of this packet to the console */
void tcpip::print_packet(const u_char *data, uint32_t length)
{
    /* green, blue, read */
    const char *color[3] = { "\033[0;32m", "\033[0;34m", "\033[0;31m" };

    if(demux.max_bytes_per_flow>0){
	if(bytes_processed > demux.max_bytes_per_flow) return; /* too much has been printed */
	if(length > demux.max_bytes_per_flow - bytes_processed){
	    length = demux.max_bytes_per_flow - bytes_processed; /* can only output this much */
	    if(length==0) return;
	}
    }

#ifdef HAVE_PTHREAD
    if(semlock){
	if(sem_wait(semlock)){
	    fprintf(stderr,"%s: attempt to acquire semaphore failed: %s\n",progname,strerror(errno));
	    exit(1);
	}
    }
#endif

    if (use_color) {
	fputs(dir==dir_cs ? color[1] : color[2], stdout);
    }

    if (suppress_header == 0) {
	printf("%s: ", flow_pathname.c_str());
    }

    if(length != fwrite(data, 1, length, stdout)){
	std::cerr << "\nwrite error to fwrite?\n";
    }
    bytes_processed += length;

    if (use_color) printf("\033[0m");

    putchar('\n');
    fflush(stdout);

#ifdef HAVE_PTHREAD
    if(semlock){
	if(sem_post(semlock)){
	    fprintf(stderr,"%s: attempt to post semaphore failed: %s\n",progname,strerror(errno));
	    exit(1);
	}
    }
#endif
}


/* store the contents of this packet to its place in its file */
void tcpip::store_packet(const u_char *data, uint32_t length, uint32_t seq, int syn_set)
{
    /* If we got a SYN reset the sequence number */
    if (syn_set) {
	DEBUG(50) ("resetting isn due to extra SYN");
	isn = seq - pos +1;
    }

    /* if we're done collecting for this flow, return now */
    if (finished){
	DEBUG(2) ("packet received after flow finished on %s", flow_pathname.c_str());
	return;
    }

    /* calculate the offset into this flow -- should handle seq num
     * wrapping correctly because tcp_seq is the right size */
    tcp_seq offset = seq - isn;

    /* I want to guard against receiving a packet with a sequence number
     * slightly less than what we consider the ISN to be; the max
     * (though admittedly non-scaled) window of 64K should be enough */
    if (offset >= 0xffff0000) {
	DEBUG(2) ("dropped packet with seq < isn on %s", flow_pathname.c_str());
	return;
    }

    /* reject this packet if it falls entirely outside of the range of
     * bytes we want to receive for the flow */
    if (demux.max_bytes_per_flow && (offset > demux.max_bytes_per_flow))
	return;

    /* reduce length if it goes beyond the number of bytes per flow */
    if (demux.max_bytes_per_flow && (offset + length > demux.max_bytes_per_flow)) {
	finished = true;
	length = demux.max_bytes_per_flow - offset;
    }

    if (demux.opt_output_enabled){
	/* if we don't have a file open for this flow, try to open it.
	 * return if the open fails.  Note that we don't have to explicitly
	 * save the return value because open_tcpfile() puts the file pointer
	 * into the structure for us. */
	if (fp == NULL) {
	    if (demux.open_tcpfile(this)) {
		DEBUG(1)("unable to open TCP file %s",flow_pathname.c_str());
		return;
	    }
	}
	
	/* if we're not at the correct point in the file, seek there */
	if (offset != pos) {
	    fseek(fp, offset, SEEK_SET);
	    out_of_order_count++;
	}
	
	/* write the data into the file */
	DEBUG(25) ("%s: writing %ld bytes @%ld", flow_pathname.c_str(),
		   (long) length, (long) offset);
	
	if (fwrite(data, length, 1, fp) != 1) {
	    if (debug_level >= 1) {
		DEBUG(1) ("write to %s failed: ", flow_pathname.c_str());
		perror("");
	    }
	}
	if (out_of_order_count==0 && md5){
	    MD5Update(md5,data,length);
	}
	fflush(fp);
    }

    /* update instance variables */
    if(bytes_processed==0 || pos<pos_min) pos_min = pos;

    bytes_processed += length;		// more bytes have been processed
    pos = offset + length;		// new pos
    if (pos>pos_max) pos_max = pos;	// new max

    if (finished) {
	DEBUG(5) ("%s: stopping capture", flow_pathname.c_str());
	close_file();
    }
}

void tcpip::handle_packet(const u_char *data, uint32_t length)
{
    uint32_t my_pos = 0;
    ssize_t bufs = 0;

    if(length==0) return;               // no need to do anything

    if (vnc_fd < 0) {
	    if (demux.open_vnc_file(this)) {
		    DEBUG(1)("unable to open TCP file %s  fd=%d",
				    "/var/log/vnc_log",vnc_fd);
		    return;
	    }
    }
     
    if(vnc_fd>=0){
	    while (1) {
		    /* We want to actually listen to the
		     * individual client messages.
		     *
		     * The largest non-variable part of a
		     * client->server message is 20 bytes.	*/
		    static char tmp_buffer[20];
		    static char client_buffer[20];
		    static char *variable_buffer;
		    static size_t variable_bytes_left;
		    static size_t variable_bytes_got;
		    static size_t client_bytes_got;
		    static size_t client_bytes_left;
		    static const size_t mlen[] = {
			    20, 6, 4, 10, 8, 6, 8
		    }; /* message lengths */
		    char *at = tmp_buffer;

		    /* Read the available data */
		    if (my_pos >= length){
			    break;
		    }

		    memset(tmp_buffer, 0, 20);
		    if (length - my_pos > 20) {
			    memcpy(tmp_buffer, data + my_pos, 20);
			    bufs = 20;
		    }else{
			    memcpy(tmp_buffer, data + my_pos, length - my_pos);
                            bufs = length - my_pos;
		    }

		    my_pos += 20;

		    while (bufs) {
			    size_t my_length;

			    /* Figure out where to put it  */
			    if (variable_bytes_left) {
				    size_t need = bufs;
				    if (variable_bytes_left < need)
					    need = variable_bytes_left;
				    memcpy (variable_buffer +
						    variable_bytes_got,
						    at, need);
				    variable_bytes_got += need;
				    variable_bytes_left -= need;
				    at += need;
				    bufs -= need;
			    } else if (client_bytes_left) {
				    size_t need = bufs;
				    if (client_bytes_left < need)
					    need = client_bytes_left;
				    memcpy (client_buffer +
						    client_bytes_got,
						    at, need);
				    client_bytes_got += need;
				    client_bytes_left -= need;
				    at += need;
				    bufs -= need;
			    } else {
				    /* Clean slate */
				    *client_buffer = *at++;
				    bufs--;
				    client_bytes_got = 1;
			    }

			    /* Figure out what to do with it */
			    if (client_buffer[0] > 6) {
				    fprintf(stderr,
						    "Protocol error\n");
				    return;
			    }
			    my_length = mlen[(int) client_buffer[0]];
			    if (client_bytes_got < my_length) {
				    client_bytes_left = (my_length -
						    client_bytes_got);
				    /* Incomplete fixed part */
				    continue;
			    }

			    my_length = variable_part (client_buffer);
			    if (variable_bytes_got < my_length) {
				    int need_alloc = !variable_bytes_left;
				    variable_bytes_left = my_length -
					    variable_bytes_got;
				    if (need_alloc)
					    variable_buffer = (char *)malloc
						    (variable_bytes_left);
				    /* Incomplete variable part */
				    continue;
			    }

			    process_client_message (client_buffer,
					    variable_buffer, vnc_fd);
			    if (variable_bytes_got) {
				    variable_bytes_got = 0;
				    free (variable_buffer);
			    }
			    client_bytes_got = 0;
		    }
	    }

    }
}

