#Detect Redhat or Debian platform
# The following variable will be set
# $PLATFORM		Debian	Redhat		none

# $BIT_MODE		32|64


if ( NOT WINDOWS )	

	if (${CMAKE_SYSTEM_PROCESSOR} MATCHES i386|i586|i686)
		set ( BIT_MODE "32")
	else ()
		set ( BIT_MODE "64")
	endif ()

	if(EXISTS "/etc/debian_version")
	   set ( PLATFORM "Debian")
	endif(EXISTS "/etc/debian_version")

	if(EXISTS "/etc/redhat-release")
	   set ( PLATFORM "Redhat")
	endif(EXISTS "/etc/redhat-release")

endif ( NOT WINDOWS )	

