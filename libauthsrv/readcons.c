#include <readpassphrase.h>

#include <u.h>
#include <libc.h>
#include <authsrv.h>

/*
 *  prompt for a string with a possible default response
 */
char*
readcons(char *prompt, char *def, int raw)
{
	char *result, msg[128], buf[1024];
	if(def)
		sprintf(msg, "%s[%s]: ", prompt, def); 
	else
		sprintf(msg, "%s: ", prompt);

	if(raw)
		result = readpassphrase(msg, buf, sizeof(buf), RPP_ECHO_OFF);
	else
		result = readpassphrase(msg, buf, sizeof(buf), RPP_ECHO_ON);

	return strdup(result);
}
