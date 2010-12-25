#if defined(WIN32) && !defined(_MSC_VER)
#include <windows.h>
#ifndef va_copy
#define va_copy(d,s) ((d) = (s))
#endif
#else
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#endif

int ourfa_vasprintf( char **ret, const char *fmt, va_list ap )
{
  int wanted;
  va_list ap_copy;

  va_copy(ap_copy, ap);

#ifdef _MSC_VER
  wanted = _vscprintf(fmt, ap);
#else
  wanted = vsnprintf( *ret = NULL, 0, fmt, ap );
#endif
  if( (wanted > 0) && ((*ret = malloc( 1 + wanted )) != NULL) )
    return vsprintf( *ret, fmt, ap_copy );

  va_end(ap_copy);

  return wanted;
}

int ourfa_asprintf( char **res, const char *fmt, ... )
{
  int retval;
  va_list argv;
  va_start( argv, fmt );
  retval = ourfa_vasprintf(res, fmt, argv );
  va_end( argv );
  return retval;
}

#ifdef _MSC_VER
int ourfa_snprintf(char *str, size_t size, const char *format, ...)
{
  int retval;
  va_list argv;
  va_start( argv, format );
  retval = _vsnprintf(str, size, format, argv);
  va_end( argv );
  if (((retval < 0) || (retval == size))
	&& str
	&& (size > 0))
	  str[size-1]='\0';
  if (errno == ERANGE)
    errno = 0;
  return retval == size ? retval-1 : retval;
}
#endif


