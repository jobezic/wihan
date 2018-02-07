#!/bin/sh

#
# This is the hotspot.cgi redirect script for wihan_redirect.
#
# Please, make your change according to your needs:
# 1. customize the redirect url by modifying the hotspot.geenkle.com url with yours.
# 2. change the default listening interface (br0) with yours.
#

echo "Content-type: text/html"
echo ""

MAC_ADDRESS=$(cat /proc/net/arp | grep $REMOTE_ADDR | awk {'print $4'} | tr ':' '-')
DEVICE_MAC=$(cat /sys/class/net/br0/address | tr ':' '-')

if [ "$QUERY_STRING" = "" ]; then
        CNS=$(echo "$HTTP_USER_AGENT" | grep -o CaptiveNetworkSupport)

        if [ "$CNS" = "CaptiveNetworkSupport" ]; then
                echo "<html>
         <!--
         <?xml version=\"1.0\" encoding=\"UTF-8\"?>
   <WISPAccessGatewayParam xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://www.wballiance.net/wispr_2_0.xsd">
<Redirect>
<MessageType>100</MessageType>
<ResponseCode>0</ResponseCode>
<VersionHigh>2.0</VersionHigh>
<VersionLow>1.0</VersionLow>
<AccessProcedure>1.0</AccessProcedure>
<AccessLocation>Hotspot Login</AccessLocation>
<LocationName>Hotspot</LocationName>
<LoginURL>http://hotspot.net/?r=1</LoginURL>
</Redirect>
</WISPAccessGatewayParam>
         --></html>"
         else

          echo "<html>
          <head>
            <title>Redirecting</title>
            <META http-equiv=\"refresh\" content=\"0;URL=http://hotspot.geenkle.com/hotspot/login.php?nas=$DEVICE_MAC&mac=$MAC_ADDRESS\">
          </head> <body></body></html>"
          fi

else
# Redirection
LOGIN=$(echo "$QUERY_STRING" | cut -d'&' -f1 )
if [ "$LOGIN" == "login=true" ]; then
    URL_REDIRECT=$(echo "$QUERY_STRING" | cut -d'&' -f2 | cut -d'=' -f2)

    MACT=$(echo $MAC_ADDRESS | tr '[:lower:]' '[:upper:]')

    cat /tmp/wihand.status | grep $MACT | awk '{ print $2}' | grep A > /dev/null 2>&1

    if [ $? -eq 0 ]; then

    URL_DEC=$(printf '%b' "${URL_REDIRECT//%/\\x}")

    sleep 1

    echo "<html>
      <head>
         <title>Redirecting</title>
         <META http-equiv=\"refresh\" content=\"0;URL=$URL_DEC\">
       </head>
       <body>
       </body>
     </html>"

    else
    echo "<html>
    <head>
    <title></title>
    </head>
    <body>
    <h1>Not authorized!</h1>
    </body>
    </html>"
    fi

  fi

fi
