/*
 * Simson's XML output class.
 * Ideally include this AFTER your config file with the HAVE statements.
 */

#ifndef _XML_H_
#define _XML_H_

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdio.h>
#include <fstream>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <inttypes.h>

/* c++ */
#include <sstream>
#include <string>
#include <stack>
#include <set>
#include <map>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#ifndef __BEGIN_DECLS
#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS     }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

#ifdef HAVE_LIBTSK3
#include <tsk3/libtsk.h>
#endif

//#pragma GCC diagnostic ignored "-Weffc++"

#ifdef __cplusplus
class xml {
private:
    /*** neither copying nor assignment is implemented ***
     *** We do this by making them private constructors that throw exceptions. ***/
    class not_impl: public std::exception {
	virtual const char *what() const throw() {
	    return "copying feature_recorder objects is not implemented.";
	}
    };
    xml(const xml &fr):	M(),
	outf(),out(),tags(),tag_stack(),tempfilename(),tempfile_template(),t0(),
	make_dtd(),outfilename(){
	throw new not_impl();
    }
    const xml &operator=(const xml &x){ throw new not_impl(); }
    /****************************************************************/

#ifdef HAVE_PTHREAD
    pthread_mutex_t M;				// mutext protecting out
#else
    int M;				// placeholder
#endif
    std::fstream outf;
    std::ostream *out;				// where it is being written; defaulst to stdout
    std::set<std::string> tags;			// XML tags
    std::stack<std::string>tag_stack;
    std::string  tempfilename;
    std::string  tempfile_template;
    struct timeval t0;
    bool  make_dtd;
    std::string outfilename;
    void  write_doctype(std::fstream &out);
    void  write_dtd();
    void  verify_tag(std::string tag);
    void  spaces();			// print spaces corresponding to tag stack
    static std::string xml_PRId64;	// for compiler bug
    static std::string xml_PRIu64;	// for compiler bug
public:
    static std::string make_command_line(int argc,char * const *argv){
	std::string command_line;
	for(int i=0;i<argc;i++){
	    if(i>0) command_line.push_back(' ');
	    command_line.append(argv[i]);
	}
	return command_line;
    }

    class existing {
    public:;
	std::map<std::string,std::string> *tagmap;
	std::string *tagid;
	const std::string *attrib;
	std::set<std::string> *tagid_set;
    };

    xml();					 // defaults to stdout
    xml(const std::string &outfilename,bool makeDTD); // write to a file, optionally making a DTD
    xml(const std::string &outfilename,class existing &e); // open an existing file, for appending
    virtual ~xml(){};
    void set_tempfile_template(const std::string &temp);

    static std::string xmlescape(const std::string &xml);
    static std::string xmlstrip(const std::string &xml);

    /**
     * opens an existing XML file and jumps to the end.
     * @param tagmap  - any keys that are tags capture the values.
     * @param tagid   - if a tagid is provided, fill tagid_set with all of the tags seen.
     */
    typedef std::map<std::string,std::string> tagmap_t;
    typedef std::set<std::string> tagid_set_t;
    void open_existing(tagmap_t *tagmap,std::string *tagid,const std::string *attrib,tagid_set_t *tagid_set);
    void close();			// writes the output to the file

    void tagout( const std::string &tag,const std::string &attribute);
    void push(const std::string &tag,const std::string &attribute);
    void push(const std::string &tag) {push(tag,"");}

    // writes a std::string as parsed data
    void puts(const std::string &pdata);

    // writes a std::string as parsed data
    void printf(const char *fmt,...) __attribute__((format(printf, 2, 3))); // "2" because this is "1"
    void pop();	// close the tag

    void add_DFXML_build_environment();
#if defined(HAVE_ASM_CPUID) && defined(__i386__)
    static void cpuid(uint32_t op, unsigned long *eax, unsigned long *ebx,
	       unsigned long *ecx, unsigned long *edx);
    void add_cpuid();
#endif
    void add_DFXML_execution_environment(const std::string &command_line);
    void add_DFXML_creator(const std::string &program,const std::string &version,
			   const std::string &svn_r,
			   const std::string &command_line){
	push("creator","version='1.0'");
	xmlout("program",program);
	xmlout("version",version);
	if(svn_r.size()>0) xmlout("svn_version",svn_r);
	add_DFXML_build_environment();
	add_DFXML_execution_environment(command_line);
	pop();			// creator
    }
    void add_rusage();

    /**********************************************
     *** THESE ARE THE ONLY THREADSAFE ROUTINES ***
     **********************************************/
    void xmlcomment(const std::string &comment);
    void xmlprintf(const std::string &tag,const std::string &attribute,const char *fmt,...) 
	__attribute__((format(printf, 4, 5))); // "4" because this is "1";
    void xmlout( const std::string &tag,const std::string &value, const std::string &attribute, const bool escape_value);

    /* These all call xmlout or xmlprintf which already has locking */
    void xmlout( const std::string &tag,const std::string &value){ xmlout(tag,value,"",true); }
    void xmlout( const std::string &tag,const int value){ xmlprintf(tag,"","%d",value); }
    void xmloutl(const std::string &tag,const long value){ xmlprintf(tag,"","%ld",value); }
#ifdef WIN32
    void xmlout( const std::string &tag,const int64_t value){ xmlprintf(tag,"","%I64d",value); }
    void xmlout( const std::string &tag,const uint64_t value){ xmlprintf(tag,"","%I64u",value); }
#else
    void xmlout( const std::string &tag,const int64_t value){ xmlprintf(tag,"",xml_PRId64.c_str(),value); }
    void xmlout( const std::string &tag,const uint64_t value){ xmlprintf(tag,"",xml_PRIu64.c_str(),value); }
#endif
    void xmlout( const std::string &tag,const double value){ xmlprintf(tag,"","%f",value); }
    void xmlout( const std::string &tag,const struct timeval &ts) {
	xmlprintf(tag,"","%d.%06d",(int)ts.tv_sec, (int)ts.tv_usec);
    }
    static std::string to8601(const struct timeval &ts) {
	struct tm tm;
	char buf[64];
#ifdef HAVE_LOCALTIME_R
	localtime_r(&ts.tv_sec,&tm);
#else
	time_t t = ts.tv_sec;
	tm = *localtime(&t);
#endif
	strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%S",&tm);
	if(ts.tv_usec>0){
	    int len = strlen(buf);
	    snprintf(buf+len,sizeof(buf)-len,".%06d",(int)ts.tv_usec);
	}
	strcat(buf,"Z");
	return std::string(buf);
    }
	
};
#endif

#endif
