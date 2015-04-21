/**
 * implementation for C++ XML generation class
 *
 * The software provided here is released by the Naval Postgraduate
 * School, an agency of the U.S. Department of Navy.  The software
 * bears no warranty, either expressed or implied. NPS does not assume
 * legal liability nor responsibility for a User's use of the software
 * or the results of such use.
 *
 * Please note that within the United States, copyright protection,
 * under Section 105 of the United States Code, Title 17, is not
 * available for any work of the United States Government and/or for
 * any works created by United States Government employees. User
 * acknowledges that this software contains work which was created by
 * NPS government employees and is therefore in the public domain and
 * not subject to copyright.
 */


#include "config.h"
#ifdef WIN32
#include <winsock2.h>
#endif

#include <errno.h>
#include <unistd.h>

#include "xml.h"

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
#include <regex.h>
#endif


#ifdef HAVE_PTHREAD
#define MUTEX_LOCK(M)   pthread_mutex_lock(M)
#define MUTEX_UNLOCK(M) pthread_mutex_unlock(M)
#else
#define MUTEX_LOCK(M)   {}
#define MUTEX_UNLOCK(M) {}
#endif

using namespace std;

#include <iostream>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <assert.h>
#include <fcntl.h>
#include <stack>

static const char *xml_header = "<?xml version='1.0' encoding='UTF-8'?>\n";

// Implementation of mkstemp for windows found on pan-devel mailing
// list archive
// @http://www.mail-archive.com/pan-devel@nongnu.org/msg00294.html
#ifndef _S_IREAD
#define _S_IREAD 256
#endif

#ifndef _S_IWRITE
#define _S_IWRITE 128
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef _O_SHORT_LIVED
#define _O_SHORT_LIVED 0
#endif

#ifndef HAVE_MKSTEMP
int mkstemp(char *tmpl)
{
   int ret=-1;
   mktemp(tmpl);
   ret=open(tmpl,O_RDWR|O_BINARY|O_CREAT|O_EXCL|_O_SHORT_LIVED, _S_IREAD|_S_IWRITE);
   return ret;
}
#endif


#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef _O_SHORT_LIVED
#define _O_SHORT_LIVED 0
#endif


std::string xml::xml_PRId64("%"PRId64);	// gets around compiler bug
std::string xml::xml_PRIu64("%"PRIu64);	// gets around compiler bug

static const char *cstr(const string &str){
    return str.c_str();
}

#if defined(HAVE_REGCOMP)
/** A local class for regex matching with a single pattern */
class Regex {
public:
    regex_t reg;
    Regex(const char *pat):reg(){
	memset(&reg,0,sizeof(reg));
	if(regcomp(&reg,pat,REG_EXTENDED)){
	    cerr << "xml.cpp: invalid regex pattern" << pat << "\n";
	    exit(1);
	}
    }
    ~Regex(){
	regfree(&reg);
    }
    string search(const string &line){
	regmatch_t ary[2];
	memset(ary,0,sizeof(ary));
	if(regexec(&reg,cstr(line),2,ary,0)==0){
	    return string(cstr(line)+ary[1].rm_so,ary[1].rm_eo-ary[1].rm_so);
	}
	else {
	    return string();
	}
    }
};
#endif

static string xml_lt("&lt;");
static string xml_gt("&gt;");
static string xml_am("&amp;");
static string xml_ap("&apos;");
static string xml_qu("&quot;");

string xml::xmlescape(const string &xml)
{
    string ret;
    for(string::const_iterator i = xml.begin(); i!=xml.end(); i++){
	switch(*i){
	case '>':  ret += xml_gt; break;
	case '<':  ret += xml_lt; break;
	case '&':  ret += xml_am; break;
	case '\'': ret += xml_ap; break;
	case '"':  ret += xml_qu; break;
	case '\000': break;		// remove nulls
	default:
	    ret += *i;
	}
    }
    return ret;
}

/**
 * Strip an XML string as necessary for a tag name.
 */

string xml::xmlstrip(const string &xml)
{
    string ret;
    for(string::const_iterator i = xml.begin(); i!=xml.end(); i++){
	if(isprint(*i) && !strchr("<>\r\n&'\"",*i)){
	    ret += isspace(*i) ? '_' : tolower(*i);
	}
    }
    return ret;
}

#include <iostream>
#include <streambuf>

#ifdef _MSC_VER
# include <io.h>
#else
# include <unistd.h>
#endif


/* This goes to stdout */
xml::xml():M(),outf(),out(&cout),tags(),tag_stack(),tempfilename(),tempfile_template("/tmp/xml_XXXXXXXX"),
	   t0(),make_dtd(false),outfilename()
{
#ifdef HAVE_PTHREAD
    pthread_mutex_init(&M,NULL);
#endif
    gettimeofday(&t0,0);
    *out << xml_header;
}

/* This should be rewritten so that the temp file is done on close, not on open */
xml::xml(const std::string &outfilename_,bool makeDTD):
    M(),outf(outfilename_.c_str(),ios_base::out),
    out(),tags(),tag_stack(),tempfilename(),tempfile_template(outfilename_+"_tmp_XXXXXXXX"),
    t0(),make_dtd(false),outfilename(outfilename_)
{
#ifdef HAVE_PTHREAD
    pthread_mutex_init(&M,NULL);
#endif
    gettimeofday(&t0,0);
    if(!outf.is_open()){
	perror(outfilename_.c_str());
	exit(1);
    }
    out = &outf;						// use this one instead
    *out << xml_header;
}

#if defined(HAVE_REGCOMP)
/**
 * opening an existing DFXML file...
 * Scan through and see if we can process.
 * We can only process XML in which tags are on lines by themselves or else both open and close are on the same line.
 */
xml::xml(const std::string &outfilename_,class existing &e):
    M(),outf(), out(),tags(),tag_stack(),tempfilename(),tempfile_template(),
    t0(),make_dtd(false),outfilename(outfilename_)
{
#ifdef HAVE_PTHREAD
    pthread_mutex_init(&M,NULL);
#endif
    gettimeofday(&t0,0);

    outf.open(outfilename.c_str(),ios_base::in|ios_base::out);
    if(!outf.is_open()){
    	cerr << outfilename << strerror(errno) << ": Cannot open\n";
	exit(1);
    }
    out = &outf;
    // Scan all of the lines, looking for elements in tagmap
    Regex tag_beg("<([^/> ]+)");
    Regex tag_end("</([^> ]+)");
    Regex tag_val(">([^<]*)<");

    // compute the regular expression to get the attribute
    string areg("=((\'[^\']+\')|(\"[^\"]+\"))");
    if(e.attrib) areg = *(e.attrib) + areg;

    Regex tag_attrib(areg.c_str());

    std::string line;
    int linenumber = 0;
    while(getline(outf,line)){
	linenumber++;
	string begs = tag_beg.search(line);
	string ends = tag_end.search(line);

	if(ends.size()==0 && line.find("/>")!=string::npos) ends=begs; // handle <value foo='bar'/>

	if(begs.size()>0 && ends.size()==0){
	    tag_stack.push(begs);
	}

	if(begs.size()==0 && ends.size()>0){
	    string popped = tag_stack.top();
	    tag_stack.pop();
	    if(ends != popped){
		cerr << "xml is inconsistent at line " << linenumber << ".\n" 
		     << "expected: " << popped << "\n"
		     << "saw:      " << ends << "\n";
		exit(1);
	    }
	}

	if(e.tagmap && begs.size()>0 && begs==ends && e.tagmap->find(begs)!=e.tagmap->end()){
	    (*e.tagmap)[begs] = tag_val.search(line);
	}

	if(e.tagid && e.tagid_set && (*e.tagid)==begs){
	    string a = tag_attrib.search(line);
	    if(a.size()>0) a = a.substr(1,a.size()-2);
	    (*e.tagid_set).insert(a);
	}
    }
}
#endif



void xml::set_tempfile_template(const std::string &temp)
{
    tempfile_template = temp;
}




void xml::close()
{
    MUTEX_LOCK(&M);
    outf.close();
    if(make_dtd){
	/* If we are making the DTD, then we should close the file,
	 * scan the output file for the tags, write to a temp file, and then
	 * close the temp file and have it overwrite the outfile.
	 */

	std::ifstream in(cstr(tempfilename));
	if(!in.is_open()){
	    cerr << tempfilename << strerror(errno) << ":Cannot re-open for input\n";
	    exit(1);
	}
	outf.open(cstr(outfilename),ios_base::out);
	if(!outf.is_open()){
	    cerr << outfilename << " " << strerror(errno)
		 << ": Cannot open for output; will not delete " << tempfilename << "\n";
	    exit(1);
	}
	// copy over first line --- the XML header
	std::string line;
	getline(in,line);
	outf << line;

	write_dtd();			// write the DTD
	while(!in.eof()){
	    getline(in,line);
	    outf << line << endl;
	}
	in.close();
	unlink(cstr(tempfilename));
	outf.close();
    }
    MUTEX_UNLOCK(&M);
}

void xml::write_dtd()
{
    *out << "<!DOCTYPE fiwalk\n";
    *out << "[\n";
    for(set<string>::const_iterator it = tags.begin(); it != tags.end(); it++){
	*out << "<!ELEMENT " << *it << "ANY >\n";
    }
    *out << "<!ATTLIST volume startsector CDATA #IMPLIED>\n";
    *out << "<!ATTLIST run start CDATA #IMPLIED>\n";
    *out << "<!ATTLIST run len CDATA #IMPLIED>\n";
    *out << "]>\n";
}

/**
 * make sure that a tag is valid and, if so, add it to the list of tags we use
 */
void xml::verify_tag(string tag)
{
    if(tag[0]=='/') tag = tag.substr(1);
    if(tag.find(" ") != string::npos){
	cerr << "tag '" << tag << "' contains space. Cannot continue.\n";
	exit(1);
    }
    tags.insert(tag);
}

void xml::puts(const string &v)
{
    *out << v;
}

void xml::spaces()
{
    for(unsigned int i=0;i<tag_stack.size();i++){
	*out << "  ";
    }
}

void xml::tagout(const string &tag,const string &attribute)
{
    verify_tag(tag);
    *out << "<" << tag;
    if(attribute.size()>0) *out << " " << attribute;
    *out << ">";
}

#if (!defined(HAVE_VASPRINTF)) || defined(_WIN32)
#ifndef _WIN32
#define ms_printf __print
#define __MINGW_ATTRIB_NONNULL(x) 
#endif
extern "C" {
    /**
     * We do not have vasprintf.
     * We have determined that vsnprintf() does not perform properly on windows.
     * So we just allocate a huge buffer and then strdup() and hope!
     */
    int vasprintf(char **ret,const char *fmt,va_list ap)
	__attribute__((__format__(ms_printf, 2, 0))) 
	__MINGW_ATTRIB_NONNULL(2) ;
    int vasprintf(char **ret,const char *fmt,va_list ap) 
    {
	/* Figure out how long the result will be */
	char buf[65536];
	int size = vsnprintf(buf,sizeof(buf),fmt,ap);
	if(size<0) return size;
	/* Now allocate the memory */
	*ret = (char *)strdup(buf);
	return size;
    }
}
#endif


void xml::printf(const char *fmt,...)
{
    va_list ap;
    va_start(ap, fmt);

    /** printf to stream **/
    char *ret = 0;
    if(vasprintf(&ret,fmt,ap) < 0){
	*out << "xml::xmlprintf: " << strerror(errno);
	exit(EXIT_FAILURE);
    }
    *out << ret;
    free(ret);
    /** end printf to stream **/

    va_end(ap);
}

void xml::push(const string &tag,const string &attribute)
{
    spaces();
    tag_stack.push(tag);
    tagout(tag,attribute);
    *out << '\n';
}

void xml::pop()
{
    assert(tag_stack.size()>0);
    string tag = tag_stack.top();
    tag_stack.pop();
    spaces();
    tagout("/"+tag,"");
    *out << '\n';
}


#if defined(HAVE_ASM_CPUID) && defined(__i386__)
void xml::cpuid(uint32_t op, unsigned long *eax, unsigned long *ebx,
                unsigned long *ecx, unsigned long *edx) {
#if defined(__PIC__)
    __asm__ __volatile__("pushl %%ebx      \n\t" /* save %ebx */
                         "cpuid            \n\t"
                         "movl %%ebx, %1   \n\t" /* save what cpuid just put in %ebx */
                         "popl %%ebx       \n\t" /* restore the old %ebx */
                         : "=a"(*eax), "=r"(*ebx), "=c"(*ecx), "=d"(*edx)
                         : "a"(op)
                         : "cc");
#else
    __asm__ __volatile__("cpuid"
                         : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                         : "a"(op)
                         : "cc");

#endif
}



void xml::add_cpuid()
{
#ifndef __WORDSIZE
#define __WORDSIZE 32
#endif
#define b(val, base, end) ((val << (__WORDSIZE-end-1)) >> (__WORDSIZE-end+base-1))
    unsigned long eax, ebx, ecx, edx;
    cpuid(0, &eax, &ebx, &ecx, &edx);
    
    char buf[256];
    snprintf(buf,sizeof(buf),"%.4s%.4s%.4s", (char *)&ebx, (char *)&edx, (char *)&ecx);
    push("cpuid");
    xmlout("identification",buf);

    cpuid(1, &eax, &ebx, &ecx, &edx);
    xmlout("family", (int64_t) b(eax, 8, 11));
    xmlout("model", (int64_t) b(eax, 4, 7));
    xmlout("stepping", (int64_t) b(eax, 0, 3));
    xmlout("efamily", (int64_t) b(eax, 20, 27));
    xmlout("emodel", (int64_t) b(eax, 16, 19));
    xmlout("brand", (int64_t) b(ebx, 0, 7));
    xmlout("clflush_size", (int64_t) b(ebx, 8, 15) * 8);
    xmlout("nproc", (int64_t) b(ebx, 16, 23));
    xmlout("apicid", (int64_t) b(ebx, 24, 31));
    
    cpuid(0x80000006, &eax, &ebx, &ecx, &edx);
    xmlout("L1_cache_size", (int64_t) b(ecx, 16, 31) * 1024);
    pop();
}
#endif

void xml::add_DFXML_execution_environment(const std::string &command_line)
{

    push("execution_environment");
#if defined(HAVE_ASM_CPUID) && defined(__i386__)
    add_cpuid();
#endif


#ifdef HAVE_SYS_UTSNAME_H
    struct utsname name;
    if(uname(&name)==0){
	xmlout("os_sysname",name.sysname);
	xmlout("os_release",name.release);
	xmlout("os_version",name.version);
	xmlout("host",name.nodename);
	xmlout("arch",name.machine);
    }
#else
#ifdef UNAMES
    xmlout("os_sysname",UNAMES,"",false);
#endif
#ifdef HAVE_GETHOSTNAME
    {
	char hostname[1024];
	if(gethostname(hostname,sizeof(hostname))==0){
	    xmlout("host",hostname);
	}
    }
#endif
#endif	
    
    xmlout("command_line", command_line); // quote it!
#ifdef HAVE_GETUID
    xmlprintf("uid","","%d",getuid());
#ifdef HAVE_GETPWUID
    xmlout("username",getpwuid(getuid())->pw_name);
#endif
#endif
    
#ifdef _MSC_VER
#define TM_FORMAT "%Y-%m-%dT%H:%M:%SZ"
#else
#define TM_FORMAT "%FT%TZ"
#endif

    char buf[256];
    time_t t = time(0);
    strftime(buf,sizeof(buf),TM_FORMAT,gmtime(&t));
    xmlout("start_time",buf);
    pop();			// <execution_environment>
}


void xml::add_rusage()
{
#ifdef HAVE_GETRUSAGE
    struct rusage ru;
    memset(&ru,0,sizeof(ru));
    if(getrusage(RUSAGE_SELF,&ru)==0){
	push("rusage");
	xmlout("utime",ru.ru_utime);
	xmlout("stime",ru.ru_stime);
	xmloutl("maxrss",(long)ru.ru_maxrss);
	xmloutl("minflt",(long)ru.ru_minflt);
	xmloutl("majflt",(long)ru.ru_majflt);
	xmloutl("nswap",(long)ru.ru_nswap);
	xmloutl("inblock",(long)ru.ru_inblock);
	xmloutl("oublock",(long)ru.ru_oublock);

	struct timeval t1;
	gettimeofday(&t1,0);
	struct timeval t;
	
	t.tv_sec = t1.tv_sec - t0.tv_sec;
	if(t1.tv_usec > t0.tv_usec){
	    t.tv_usec = t1.tv_usec - t0.tv_usec;
	} else {
	    t.tv_sec--;
	    t.tv_usec = (t1.tv_usec+1000000) - t0.tv_usec;
	}
	xmlout("clocktime",t);
	pop();
    }
#endif
}


/****************************************************************
 *** THESE ARE THE ONLY THREADSAFE ROUTINES
 ****************************************************************/
void xml::xmlcomment(const string &comment_)
{
    MUTEX_LOCK(&M);
    *out << "<!-- " << comment_ << " -->\n";
    out->flush();
    MUTEX_UNLOCK(&M);
}


void xml::xmlprintf(const std::string &tag,const std::string &attribute, const char *fmt,...)
{
    MUTEX_LOCK(&M);    
    spaces();
    tagout(tag,attribute);
    va_list ap;
    va_start(ap, fmt);

    /** printf to stream **/
    char *ret = 0;
    if(vasprintf(&ret,fmt,ap) < 0){
	cerr << "xml::xmlprintf: " << strerror(errno) << "\n";
	exit(EXIT_FAILURE);
    }
    *out << ret;
    free(ret);
    /** end printf to stream **/

    va_end(ap);
    tagout("/"+tag,"");
    *out << '\n';
    out->flush();
    MUTEX_UNLOCK(&M);
}

void xml::xmlout(const string &tag,const string &value,const string &attribute,bool escape_value)
{
    MUTEX_LOCK(&M);
    spaces();
    if(value.size()==0){
	if(tag.size()) tagout(tag,attribute+"/");
    } else {
	if(tag.size()) tagout(tag,attribute);
	if(escape_value) *out << xmlescape(value);
	else *out << value;
	if(tag.size()) tagout("/"+tag,"");
    }
    *out << "\n";
    out->flush();
    MUTEX_UNLOCK(&M);
}

#ifdef HAVE_LIBEWF
#include <libewf.h>
#endif

#ifdef HAVE_EXIV2
#ifdef GNUC_HAS_DIAGNOSTIC_PRAGMA
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Weffc++"
#endif
#include <exiv2/image.hpp>
#include <exiv2/exif.hpp>
#include <exiv2/error.hpp>
#endif

#ifdef HAVE_LIBAFFLIB
#include <afflib/afflib.h>
#endif


/* These support Digital Forensics XML and require certain variables to be defined */
void xml::add_DFXML_build_environment()
{
    /* __DATE__ formats as: Apr 30 2011 */
    struct tm tm;
    memset(&tm,0,sizeof(tm));
    push("build_environment");
#ifdef __GNUC__
    xmlprintf("compiler","","GCC %d.%d",__GNUC__, __GNUC_MINOR__);
#endif
#if defined(__DATE__) && defined(__TIME__) && defined(HAVE_STRPTIME)
    if(strptime(__DATE__,"%b %d %Y",&tm)){
	char buf[64];
	snprintf(buf,sizeof(buf),"%4d-%02d-%02dT%s",tm.tm_year+1900,tm.tm_mon+1,tm.tm_mday,__TIME__);
	xmlout("compilation_date",buf);
    }
#endif
#ifdef HAVE_LIBTSK3
    xmlout("library", "", std::string("name=\"tsk\" version=\"") + tsk_version_get_str() + "\"",false);
#endif
#ifdef HAVE_LIBAFFLIB
    xmlout("library", "", std::string("name=\"afflib\" version=\"") + af_version() +"\"",false);
#endif
#ifdef HAVE_LIBEWF
    xmlout("library", "", std::string("name=\"libewf\" version=\"") + libewf_get_version() + "\"",false);
#endif
#ifdef HAVE_EXIV2
    xmlout("library", "", std::string("name=\"exiv2\" version=\"") + Exiv2::version() + "\"",false);
#endif
#ifdef HAVE_GNUEXIF
    // gnuexif does not have a programmatically obtainable version.
#endif
    pop();
}

