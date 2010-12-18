#if defined(WIN32) && !defined(_MSC_VER)
#include <windows.h>
#else 
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#endif

int asprintf( char **, char *, ... );
int vasprintf( char **, char *, va_list );

int vasprintf( char **sptr, char *fmt, va_list argv )
{
#ifdef _MSC_VER
  int wanted = _vscprintf(fmt, argv);
#else
  int wanted = vsnprintf( *sptr = NULL, 0, fmt, argv );
#endif
  if( (wanted > 0) && ((*sptr = malloc( 1 + wanted )) != NULL) )
    return vsprintf( *sptr, fmt, argv );

  return wanted;
}

int asprintf( char **sptr, char *fmt, ... )
{
  int retval;
  va_list argv;
  va_start( argv, fmt );
  retval = vasprintf( sptr, fmt, argv );
  va_end( argv );
  return retval;
}


