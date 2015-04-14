#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef unsigned short      uint16_t;
typedef unsigned int        uint32_t;

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
	exit (1);
}


/* For recording */
static int process_client_message (char *fixed, char *variable, FILE *f)
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

	gettimeofday (&tv, &tz);
	if (!last_tv.tv_sec && !last_tv.tv_usec)
		first_tv = last_tv = tv;
	diff.tv_sec = tv.tv_sec - last_tv.tv_sec;
	diff.tv_usec = tv.tv_usec - last_tv.tv_usec;
	ms = diff.tv_sec * 1000 + diff.tv_usec / 1000;

	if (first) {
		first = 0;
		fputs ("RFM 001.000\nshared\n", f);
	} else if (*delayed_output && (!last_was_key_down || message > 4)) {
		/* We need to output a deferred line after calculating
		 * the delay */
		if (ms > 0) {
			char *p = delayed_output + strlen (delayed_output);
			sprintf (p, " delay %dms", ms);
		}
		strcat (delayed_output, "\n");
		fputs (delayed_output, f);
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
				fprintf (f, "# At %dms from start\n", ms);
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
						fputs (delayed_output, f);
						last_tv = tv;
						*delayed_output = '\0';
						last_was_key_down = 0;
					} else {
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
							fputs (delayed_output, f);
						}
						i--;
						sprintf (delayed_output,
								"button %d %s", i,
								(buttons & (1<<i)) ? "down" : "up");
						diff ^= 1<<i;
					}
					current_buttons = buttons;
				}

				/* Now deal with position */
				if (current_x != x || current_y != y) {
					if (*delayed_output) {
						strcat (delayed_output, "\n");
						fputs (delayed_output, f);
					}
					sprintf (delayed_output,
							"pointer %d %d", x, y);
					current_x = x;
					current_y = y;
				}
				break;
			}
		case 6: /* ClientCutText */
			fputs ("# ClientCutText not supported yet\n", f);
			break;
		default:
			fprintf (stderr, "Protocol error\n");
			exit (1);
	}
	return 0;
}

void read_client(const char *src_file_name, const char *dst_file_name)
{
	ssize_t bufs = 0;
	int clientr = 0;
	FILE *f = NULL;

	clientr = open(src_file_name, O_RDONLY);

	if (-1 == clientr) {
		printf("read file [%s] error\r\n", src_file_name);
		return;
	}

	f = fopen(dst_file_name, "w+");
	if (NULL == f) {
		printf("open file [%s] error\r\n", src_file_name);
		close(clientr);
		return;
	}

	lseek(clientr, 14, SEEK_SET);

	while (1) {
		/* We want to actually listen to the
		 * individual client messages.
		 *
		 * The largest non-variable part of a
		 * client->server message is 20 bytes.  */
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
		bufs = read (clientr, tmp_buffer, 20);
		if (bufs <= 0) break;

		while (bufs) {
			size_t length;

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
				exit (1);
			}
			length = mlen[(int) client_buffer[0]];
			if (client_bytes_got < length) {
				client_bytes_left = (length -
						client_bytes_got);
				/* Incomplete fixed part */
				continue;
			}

			length = variable_part (client_buffer);
			if (variable_bytes_got < length) {
				int need_alloc = !variable_bytes_left;
				variable_bytes_left = length -
					variable_bytes_got;
				if (need_alloc)
					variable_buffer = malloc
						(variable_bytes_left);
				/* Incomplete variable part */
				continue;
			}

			process_client_message (client_buffer,
					variable_buffer, f);
			if (variable_bytes_got) {
				variable_bytes_got = 0;
				free (variable_buffer);
			}
			client_bytes_got = 0;
		}
	}

	fclose(f);
	close(clientr);
	return;
}

int main(int argc, char *argv[])
{
	read_client(argv[1], argv[2]);
}
