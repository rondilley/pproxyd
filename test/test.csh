#!/bin/csh

set i=0

while ( $i < 100 )
 echo "Test pass $i starting . . ."
 wget -q -r -i testurl.lst -O /dev/null
 echo "Test pass $i complete"
 @ i++
end

