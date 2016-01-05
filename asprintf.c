#if defined(WIN32) && !defined(_MSC_VER)
#include <windows.h>
#else
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#endif
#ifndef va_copy
#define va_copy(d,s) ((d) = (s))
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