/****
 *
 * Passive Proxy Logging Daemon - Line Parser Functions
 * 
 * Copyright (c) 2011-2015, Ron Dilley
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 ****/

/****
 *
 * defines
 *
 ****/

/****
 *
 * includes
 *
 ****/

#include "parser.h"

/****
 *
 * local variables
 *
 ****/

PRIVATE char *fields[MAX_FIELD_POS];

/****
 *
 * external global variables
 *
 ****/

extern Config_t *config;

/****
 *
 * functions
 *
 ****/

/****
 *
 * init parser
 *
 ****/

void initParser( void ) {
  /* make sure the field list of clean */
  XMEMSET( fields, 0, sizeof( char * ) * MAX_FIELD_POS );

  /* XXX it would be faster to init all mem here instead of on-demand */
}

/****
 *
 * de-init parser
 *
 ****/

void deInitParser( void ) {
  int i;

  for( i = 0; i < MAX_FIELD_POS; i++ )
    if ( fields[i] != NULL )
      XFREE( fields[i] );
}

/****
 *
 * parse that line
 *
 * pass a line to the function and the function will
 * return a printf style format string
 *
 ****/

int parseLine( char *line ) {
  int curFormPos = 0;
  int curLinePos = 0;
  int startOfField;
  int curFieldType = FIELD_TYPE_UNDEF;
  int runLen = 0;
  int i;
  char *posPtr;
  char *key = NULL;
  char *tmpString;
  long tmpOffset;
  long offsetList[1024];
  int fieldPos = 0; // 0 is where we store the template
  int offsetPos = 0;
  int templatePos = 0;
  long tmpLongNum = 0;
  int inQuotes = FALSE;

  if ( fields[fieldPos] EQ NULL ) {
    if( ( fields[fieldPos] = (char *)XMALLOC( MAX_FIELD_LEN ) ) EQ NULL ) {
      display( LOG_ERR, "Unable to allocate memory for string" );
      return( 0 );
    }
  }
  fieldPos++;

  while( line[curLinePos] != '\0' ) {

    if ( runLen >= MAX_FIELD_LEN ) {
      fprintf( stderr, "ERR - Field is too long\n" );
      return( fieldPos-1 );
    } else if ( fieldPos >= MAX_FIELD_POS ) {
      fprintf( stderr, "ERR - Too many fields in line\n" );
      return( fieldPos-1 );
    } else if ( curFieldType EQ FIELD_TYPE_STRING ) {

      /****
       *
       * string
       *
       ****/

      if ( isalnum( line[curLinePos] ) ) {

	/****
	 *
	 * add alpha numberic char to string
	 *
	 ****/

	runLen++;
	curLinePos++;
      } else if ( ( line[curLinePos] EQ '.' ) |
		  ( (inQuotes) && (line[curLinePos] EQ ',') ) |
		  ( line[curLinePos] EQ '-' ) |
		  ( (inQuotes) && (line[curLinePos] EQ ':') ) |
		  ( (inQuotes) && (line[curLinePos] EQ ';') ) |
		  ( (inQuotes) && (line[curLinePos] EQ '+') ) |
		  ( (inQuotes) && (line[curLinePos] EQ '!') ) |
		  ( (inQuotes) && (line[curLinePos] EQ '/') ) |
		  ( line[curLinePos] EQ '#' ) |
		  ( line[curLinePos] EQ '$' ) |
		  ( (inQuotes) && (line[curLinePos] EQ ' ') ) |
		  ( (inQuotes) && (line[curLinePos] EQ '(') ) |
		  ( (inQuotes) && (line[curLinePos] EQ ')') ) |
		  ( line[curLinePos] EQ '~' ) |
		  ( line[curLinePos] EQ '@' ) |
		  ( line[curLinePos] EQ '\\' ) |
		  ( line[curLinePos] EQ '_' )
		  ) {

	/****
	 *
	 * add some printable characters to the string
	 *
	 ****/

	runLen++;
	curLinePos++;

      } else if ( line[curLinePos] EQ '%' ) {

	/****
	 *
	 * add some printable characters to the string
	 *
	 ****/

	runLen++;
	curLinePos++;

      } else if ( ( line[curLinePos] EQ '\"' ) |
		  ( line[curLinePos] EQ '\'' ) ) {

	/****
	 *
	 * deal with quoted fields, spaces and some printable characters
	 * will be added to the string
	 *
	 ****/

	/* check to see if it is the start or end */

	if ( inQuotes | config->greedy ) {

	  /* extract string */

	  if ( fields[fieldPos] EQ NULL ) {
	    if( ( fields[fieldPos] = (char *)XMALLOC( MAX_FIELD_LEN ) ) EQ NULL ) {
	      fprintf( stderr, "ERR - Unable to allocate memory for string\n" );
	      return( fieldPos-1 );
	    }
	  }
	  fields[fieldPos][runLen] = '\0';
	  XMEMCPY( fields[fieldPos], line + startOfField, runLen );

#ifdef DEBUG
	  if ( config->debug >= 5 )
	    printf( "DEBUG - Extracting string [%s]\n", fields[fieldPos] );
#endif

	  /* update template */
	  if ( templatePos > ( MAX_FIELD_LEN - 4 ) ) {
	    fprintf( stderr, "ERR - Template is too long\n" );
	    return( fieldPos-1 );
	  }
	  fields[0][templatePos++] = '%';
  	  fields[0][templatePos++] = 's';
	  fields[0][templatePos++] = line[curLinePos];
  	  fields[0][templatePos] = 0;

	  fieldPos++;

	  /* switch field state */
	  curFieldType = FIELD_TYPE_UNDEF;
	  runLen = 1;
	  startOfField = ++curLinePos;
	  inQuotes = FALSE;

	} else {

	  /* at the start */
	  inQuotes = TRUE;
	  runLen++;
	  curLinePos++;
	}

      } else if ( ( line[curLinePos] EQ ':' ) |
		  ( line[curLinePos] EQ ' ' ) |
		  ( line[curLinePos] EQ '\t' ) |
		  ( line[curLinePos] EQ '=' ) ) {

	/****
	 *
	 * if these characters are in quotes, treat it as a delimeter, if not, add it to the string
	 *
	 ****/

	if ( inQuotes ) {

	  /* just add it to the string */

	  runLen++;
	  curLinePos++;

	} else {

	  /* treat it as a delimeter */

	  if ( fields[fieldPos] EQ NULL ) {
	    if( ( fields[fieldPos] = (char *)XMALLOC( MAX_FIELD_LEN ) ) EQ NULL ) {
	      fprintf( stderr, "ERR - Unable to allocate memory for string\n" );
	      return( fieldPos-1 );
	    }
	  }
	  fields[fieldPos][runLen] = '\0';
	  XMEMCPY( fields[fieldPos], line + startOfField, runLen );

#ifdef DEBUG
	  if ( config->debug >= 5 )
	    printf( "DEBUG - Extracted string [%s]\n", fields[fieldPos] );
#endif

	  /* update template */
	  if ( templatePos > ( MAX_FIELD_LEN - 3 ) ) {
	    fprintf( stderr, "ERR - Template is too long\n" );
	    return( fieldPos-1 );
	  }
	  fields[0][templatePos++] = '%';
  	  fields[0][templatePos++] = 's';
  	  fields[0][templatePos] = '\0';
	  fieldPos++;

	  /* switch field state */
	  curFieldType = FIELD_TYPE_UNDEF;

	}
   
      } else if ( ispunct( line[curLinePos] ) ) {

	/****
	 *
	 * punctuation is a delimeter
	 *
	 ****/

	if ( curLinePos > 0 ) {
	  if ( ( line[curLinePos-1] EQ ' ' ) | ( line[curLinePos-1] EQ '\t' ) ) {
	    /* last char was a blank */
	    runLen--;
	  }
	}

	/* extract string */

	if ( fields[fieldPos] EQ NULL ) {
	  if( ( fields[fieldPos] = (char *)XMALLOC( MAX_FIELD_LEN ) ) EQ NULL ) {
	    fprintf( stderr, "ERR - Unable to allocate memory for string\n" );
	    return( fieldPos-1 );
	  }
	}
	fields[fieldPos][runLen] = '\0';
	XMEMCPY( fields[fieldPos], line + startOfField, runLen );

#ifdef DEBUG
	if ( config->debug >= 5 )
	  printf( "DEBUG - Extracting string [%s]\n", fields[fieldPos] );
#endif

	/* update template */
	if ( templatePos > ( MAX_FIELD_LEN - 3 ) ) {
	  fprintf( stderr, "ERR - Template is too long\n" );
	  return( fieldPos-1 );
	}
	fields[0][templatePos++] = '%';
	fields[0][templatePos++] = 's';
	fields[0][templatePos] = '\0';
	fieldPos++;

	/* switch field state */
	curFieldType = FIELD_TYPE_UNDEF;

      } else if ( ( iscntrl( line[curLinePos] ) ) | !( isprint( line[curLinePos] ) ) ) {

	/****
	 *
	 * ignore control and non-printable characters
	 *
	 ****/

	/* extract string */

	if ( fields[fieldPos] EQ NULL ) {
	  if( ( fields[fieldPos] = (char *)XMALLOC( MAX_FIELD_LEN ) ) EQ NULL ) {
	    fprintf( stderr, "ERR - Unable to allocate memory for string\n" );
	    return( fieldPos-1 );
	  }
	}
	fields[fieldPos][runLen] = '\0';
	XMEMCPY( fields[fieldPos], line + startOfField, runLen );

#ifdef DEBUG
	if ( config->debug >= 5 )
	  printf( "DEBUG - Extracting string [%s]\n", fields[fieldPos] );
#endif

	/* update template */
	if ( templatePos > ( MAX_FIELD_LEN - 3 ) ) {
	  fprintf( stderr, "ERR - Template is too long\n" );
	  return( fieldPos-1 );
	}
	fields[0][templatePos++] = '%';
	fields[0][templatePos++] = 's';
	fields[0][templatePos] = 0;
	fieldPos++;

	/* XXX this will mess up hashing */
	curFieldType = FIELD_TYPE_UNDEF;

      }

    } else if ( curFieldType EQ FIELD_TYPE_CHAR ) {

      /****
       *
       * char field
       *
       ****/

      if ( isalnum( line[curLinePos] ) |
	   ( line[curLinePos] EQ '/' ) |
	   ( line[curLinePos] EQ '@' ) |
	   ( ( inQuotes ) && ( line[curLinePos] EQ ' ' ) ) |
	   ( line[curLinePos] EQ '\\' ) |
	   ( line[curLinePos] EQ ' ' ) |
	   ( line[curLinePos] EQ '-' ) |
	   ( line[curLinePos] EQ ':' )
	   ) {
	/* convery char to string */
	curFieldType = FIELD_TYPE_STRING;
	runLen++;
	curLinePos++;
#ifdef HAVE_ISBLANK
      } else if ( ( ispunct( line[curLinePos] ) ) | ( isblank( line[curLinePos] ) ) ) {
#else
      } else if ( ( ispunct( line[curLinePos] ) ) | ( line[curLinePos] EQ ' ' ) | ( line[curLinePos] EQ '\t' ) ) {
#endif

         /* extract char */

         if ( fields[fieldPos] EQ NULL ) {
           if( ( fields[fieldPos] = (char *)XMALLOC( MAX_FIELD_LEN ) ) EQ NULL ) {
              fprintf( stderr, "ERR - Unable to allocate memory for string\n" );
	      return( fieldPos-1 );
           }
         }
         fields[fieldPos][runLen] = '\0';
         XMEMCPY( fields[fieldPos], line + startOfField, runLen );

#ifdef DEBUG
	 if ( config->debug >= 6 )
	   printf( "DEBUG - Extracting character [%s]\n", fields[fieldPos] );
#endif
	 
	 /* update template */
	 if ( templatePos > ( MAX_FIELD_LEN - 3 ) ) {
	   fprintf( stderr, "ERR - Template is too long\n" );
	   return( fieldPos-1 );
	 }
	 fields[0][templatePos++] = '%';
	 fields[0][templatePos++] = 'c';
	 fields[0][templatePos] = '\0';
         fieldPos++;

         /* switch field state */
         curFieldType = FIELD_TYPE_UNDEF;

      } else if ( ( iscntrl( line[curLinePos] ) ) | !( isprint( line[curLinePos] ) ) ) {
	  
	/* extract character */
         if ( fields[fieldPos] EQ NULL ) {
           if( ( fields[fieldPos] = (char *)XMALLOC( MAX_FIELD_LEN ) ) EQ NULL ) {
              fprintf( stderr, "ERR - Unable to allocate memory for string\n" );
	      return( fieldPos-1 );
           }
         }
         fields[fieldPos][runLen] = '\0';
         XMEMCPY( fields[fieldPos], line + startOfField, runLen );

#ifdef DEBUG
	 if ( config->debug >= 6 )
	   printf( "DEBUG - Extracting character [%s]\n", fields[fieldPos] );
#endif
	 
	 /* update template */
	 if ( templatePos > ( MAX_FIELD_LEN - 3 ) ) {
	   fprintf( stderr, "ERR - Template is too long\n" );
	   return( fieldPos-1 );
	 }
	 fields[0][templatePos++] = '%';
	 fields[0][templatePos++] = 'c';
	 fields[0][templatePos] = '\0';
         fieldPos++;

         /* switch field state */
         curFieldType = FIELD_TYPE_UNDEF;
      }

    } else if ( curFieldType EQ FIELD_TYPE_IP4 ) {


    } else if ( curFieldType EQ FIELD_TYPE_NUM_INT ) {

      /****
       *
       * number field
       *
       ****/

      /* XXX need to add code to handle numbers beginning with 0 */
      if ( isdigit( line[curLinePos] ) ) {
	runLen++;
	curLinePos++;
      } else if ( isalpha( line[curLinePos] ) |
		  ( line[curLinePos] EQ '@' ) |
		  ( (inQuotes) && ( line[curLinePos] EQ ' ' ) ) |
		  ( line[curLinePos] EQ '\\' )
		  ) {
	/* convert field to string */
	curFieldType = FIELD_TYPE_STRING;
	runLen++;
	curLinePos++;

#ifdef HAVE_ISBLANK
      } else if ( ( ispunct( line[curLinePos] ) ) |
		  ( isblank( line[curLinePos] ) ) |
		  ( line[curLinePos] EQ '.' ) |
		  ( line[curLinePos] EQ '/' ) |
		  ( line[curLinePos] EQ ':' ) ) {
#else
      } else if ( ( ispunct( line[curLinePos] ) ) |
		  ( line[curLinePos] EQ ' ' ) |
		  ( line[curLinePos] EQ '\t' ) |
		  ( line[curLinePos] EQ '.' ) |
		  ( line[curLinePos] EQ '/' ) |
		  ( line[curLinePos] EQ ':' ) ) {
#endif

	/* extract number string */

	if ( fields[fieldPos] EQ NULL ) {
	  if( ( fields[fieldPos] = (char *)XMALLOC( MAX_FIELD_LEN ) ) EQ NULL ) {
	    fprintf( stderr, "ERR - Unable to allocate memory for string\n" );
	    return( fieldPos-1 );
	  }
	}
	fields[fieldPos][runLen] = '\0';
	XMEMCPY( fields[fieldPos], line + startOfField, runLen );

#ifdef DEBUG
	if ( config->debug >= 5 )
	  printf( "DEBUG - Extracting number [%s]\n", fields[fieldPos] );
#endif
	
	/* update template */
	if ( templatePos > ( MAX_FIELD_LEN - 3 ) ) {
	  fprintf( stderr, "ERR - Template is too long\n" );
	  return( fieldPos-1 );
	}
	fields[0][templatePos++] = '%';
	fields[0][templatePos++] = 'd';
	fields[0][templatePos] = '\0';
	fieldPos++;

	/* switch field state */
	curFieldType = FIELD_TYPE_UNDEF;

      } else if ( ( iscntrl( line[curLinePos] ) ) | !( isprint( line[curLinePos] ) ) ) {
	  
	/* extract string */

	if ( fields[fieldPos] EQ NULL ) {
	  if( ( fields[fieldPos] = (char *)XMALLOC( MAX_FIELD_LEN ) ) EQ NULL ) {
	    fprintf( stderr, "ERR - Unable to allocate memory for string\n" );
	    return( fieldPos-1 );
	  }
	}
	fields[fieldPos][runLen] = '\0';
	XMEMCPY( fields[fieldPos], line + startOfField, runLen );

#ifdef DEBUG
	if ( config->debug >= 5 )
	  printf( "DEBUG - Extracting number [%s]\n", fields[fieldPos] );
#endif

	/* update template */
	if ( templatePos > ( MAX_FIELD_LEN - 3 ) ) {
	  fprintf( stderr, "ERR - Template is too long\n" );
	  return( fieldPos-1 );
	}
	fields[0][templatePos++] = '%';
	fields[0][templatePos++] = 'd';
	fields[0][templatePos] = '\0';
	fieldPos++;

	/* switch field state */
	curFieldType = FIELD_TYPE_UNDEF;

      }

    } else if ( curFieldType EQ FIELD_TYPE_NUM_FLOAT ) {

      /****
       *
       * float
       *
       ****/

    } else if ( curFieldType EQ FIELD_TYPE_NUM_HEX ) {

      /****
       *
       * hex field
       *
       ****/

    } else if ( curFieldType EQ FIELD_TYPE_STATIC ) {

      /****
       *
       * printable, but non-alphanumeric
       *
       ****/

      /* this is a placeholder for figuring out how to handle multiple spaces */

      curFieldType = FIELD_TYPE_UNDEF;

    } else {

      /****
       *
       * begining of new field
       *
       ****/

      if ( isalpha( line[curLinePos] ) |
	   ( ( inQuotes ) && ( line[curLinePos] EQ '/' ) ) |
	   ( line[curLinePos] EQ '@' ) |
	   ( line[curLinePos] EQ '%' ) |
	   ( line[curLinePos] EQ '$' ) |
	   ( line[curLinePos] EQ '\\' )
	   ) {
	curFieldType = FIELD_TYPE_CHAR;
	runLen = 1;
	startOfField = curLinePos++;
      } else if ( isdigit( line[curLinePos] ) ) {
	curFieldType = FIELD_TYPE_NUM_INT;
	runLen = 1;
	startOfField = curLinePos++;
      } else if ( ( line[curLinePos] EQ '\"' ) |
		  ( line[curLinePos] EQ '\'' ) ) {
	if ( inQuotes ) {
	  /* something is really broke */
	  runLen++;
	  curLinePos++;
	  inQuotes = FALSE;
	} else {
	  if ( !config->greedy ) {
	    if ( templatePos > ( MAX_FIELD_LEN - 2 ) ) {
	      fprintf( stderr, "ERR - Template is too long\n" );
	      return( fieldPos-1 );
	    }
	    fields[0][templatePos++] = line[curLinePos];
	    fields[0][templatePos] = '\0';
	    curFieldType = FIELD_TYPE_STRING;
	    inQuotes = TRUE;
	    runLen = 0;
	    startOfField = ++curLinePos;
	  } else {
	    /* printable but not alpha+num */
	    if ( templatePos > ( MAX_FIELD_LEN - 2 ) ) {
	      fprintf( stderr, "ERR - Template is too long\n" );
	      return( fieldPos-1 );
	    }
	    fields[0][templatePos++] = line[curLinePos];
	    fields[0][templatePos] = '\0';
#ifdef DEBUG
	    if ( config->debug >= 10 )
	      printf( "DEBUG - Updated template [%s]\n", fields[0] );
#endif
	    curFieldType = FIELD_TYPE_STATIC;
	    runLen = 1;
	    startOfField = curLinePos++;
	  }
	}
      } else if ( ( iscntrl( line[curLinePos] ) ) | !( isprint( line[curLinePos] ) ) ) {
	/* not a valid log character, ignore it for now */
	curLinePos++;
#ifdef HAVE_ISBLANK
      } else if ( ( ispunct( line[curLinePos] ) ) |
		  ( isblank( line[curLinePos] ) ) |
		  ( isprint( line[curLinePos] ) ) ) {
#else
      } else if ( ( ispunct( line[curLinePos] ) ) |
		  ( isprint( line[curLinePos] ) ) |
		  ( line[curLinePos] EQ ' ' ) |
		  ( line[curLinePos] EQ '\t' ) ) {
#endif
	/* printable but not alpha+num */
	if ( templatePos > ( MAX_FIELD_LEN - 2 ) ) {
	  fprintf( stderr, "ERR - Template is too long\n" );
	  return( fieldPos-1 );
	}
	fields[0][templatePos++] = line[curLinePos];
	fields[0][templatePos] = '\0';
#ifdef DEBUG
	if ( config->debug >= 10 )
	  printf( "DEBUG - Updated template [%s]\n", fields[0] );
#endif
	curFieldType = FIELD_TYPE_STATIC;
	runLen = 1;
	startOfField = curLinePos++;
      } else {
	/* ignore it */
	curLinePos++;
      }
    }
  }

  /* just in case the line was 0 length */
  if ( curLinePos EQ 0 )
    return( 0 );

  return( fieldPos );
}

/****
 *
 * return parsed field
 *
 ****/

int getParsedField( char *oBuf, int oBufLen, const unsigned int fieldNum ) {
  if ( ( fieldNum >= MAX_FIELD_POS ) || ( fields[fieldNum] EQ NULL ) ) {
    fprintf( stderr, "ERR - Requested field does not exist [%d]\n", fieldNum );
        oBuf[0] = 0;
        return( FAILED );
  }
  XSTRNCPY( oBuf, fields[fieldNum], oBufLen );
  return( TRUE );
}

