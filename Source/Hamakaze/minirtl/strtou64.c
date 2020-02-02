#include "rtltypes.h"

unsigned long long strtou64_a(char *s)
{
	unsigned long long 	a = 0;
	char				c;

	if (s == 0)
		return 0;

	while (*s != 0) {
		c = *s;
		if (_isdigit_w(c))
			a = (a*10)+((unsigned long long)c-'0');
		else
			break;
		s++;
	}
	return a;
}

unsigned long long strtou64_w(wchar_t *s)
{
	unsigned long long 	a = 0;
	wchar_t				c;

	if (s == 0)
		return 0;

	while (*s != 0) {
		c = *s;
		if (_isdigit_w(c))
			a = (a*10)+((unsigned long long)c-L'0');
		else
			break;
		s++;
	}
	return a;
}
