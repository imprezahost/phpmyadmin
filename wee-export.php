<html>
<head>
   <link rel="stylesheet" type="text/css" href="gpgstyle.css" >
</head>
<body>
<?php

/*
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

*/

/************************************************************
* Copyright Ralf Senderek, Ireland 2011-2013. (http://senderek.ie)
*
* Update in 2018 by impreza.host (support@impreza.email)
*
* This file is part of the WEB ENCRYPTION EXTENSION (WEE)
* File     : wee-export.php
* Version  : 3.0
* License  : GPL-v3
* Signature: To protect the integrity of the source code, this program
*            is signed with the code signing key used by the copyright
*            holder, Ralf Senderek.
* Date     : Thursday, 24 July 2014
* Contact  : Please send enquiries and bug-reports to opensource@senderek.ie
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
*************************************************************/

// before anything else, check that data has arrived here via HTTPS
/* if ($_SERVER['HTTPS'] != "on") {
          die ("Use a secure HTTPS connection to the server. Aborting ...");
} */


if (! is_file("gpgconfig.php")){
          die ("Config file does not exist.");
}

require_once('gpgconfig.php');

if (! is_dir($GPGDIR)){
          die ("GPG directory $GPGDIR does not exist.");
}
else {
          $ERRORFILE = $GPGDIR."/gpgerrors";
}

if (! isset($KEYEXPORT)) {
          $KEYEXPORT = "no";
}

if (! isset($SECRETKEYEXPORT)) {
          $SECRETKEYEXPORT = "no";
}

if (isset($_REQUEST['keyid'])) {
          $KEYID = checkinput($_REQUEST['keyid'], "noscript");
}

if (isset($_REQUEST['keytype'])) {
          $KEYTYPE = checkinput($_REQUEST['keytype'], "noscript");
}

echo "<div class=keys>\n";

if (isset($KEYID) && isset($KEYTYPE)) {
     if ($KEYEXPORT == "yes") {
          // Key export
          echo "<h3>Key Export</h3>\n";
          $EXPORT = "";
          if (($KEYTYPE == "secretkey") && ($SECRETKEYEXPORT == "yes")) {
               $EXPORT ="/usr/bin/gpg  --homedir ".$GPGDIR." --armor --logger-file ".$ERRORFILE." --output -  --export-secret-keys \"".$KEYID."\"" ;
          }

          if ($KEYTYPE == "publickey") {
               $EXPORT ="/usr/bin/gpg  --homedir ".$GPGDIR." --armor --logger-file ".$ERRORFILE." --output -  --export \"".$KEYID."\"" ;
          }
          if (! empty($EXPORT)) {
               $RESULT = unix2 ($EXPORT,$GPGDIR);
               // check if key export is successful
               $ERR1 = strpos($RESULT,'no signed data');
               $ERR2 = strpos($RESULT,'the signature could not be verified');
               if (($ERR1 === false) && ($ERR2 === false)){
                    echo "<textarea name=result cols=65 rows=15>\n";
                    echo $RESULT;
                    echo "\n</textarea>\n";
                    echo "\n<p><input type=button value='Close' onclick='javascript:window.close();'>\n";
               }
               else {
                    echo "<h3 class=error>Key export failed.</h3>";
                    echo "<input type=button value='Close' onclick='javascript:window.close();'>\n";
               }

          }
          else {
               echo "<h3 class=error>Key export is not allowed.</h3>";
               echo "<input type=button value='Close' onclick='javascript:window.close();'>\n";
          }
     }
     else {
          echo "<h3 class=error>Key export is not allowed.</h3>";
          echo "<input type=button value='Close' onclick='javascript:window.close();'>\n";

     }
}
else {
      echo "<h3 class=error>Key export failed.</h3>\n";
      echo "<input type=button value='Close' onclick='javascript:window.close();'>\n";
}

echo "<p><center>version ".$VERSION." powered by <a href=https://impreza.host>Impreza Host</a></center><p>";
echo "\n</div>\n";

?>

<!--
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.11 (GNU/Linux)

iQIcBAEBAgAGBQJT0RHKAAoJEPv24sKOnJjdcRgP/RL9FUoJJlKLOQNhb98cw2Jd
XR1PDQkQVj6aMKE62TvSqdl1dcElOBrp0x3MpZlrZVXvSDzbEjhhSKR8HXfFgM4B
82pcLmsXjbllhaVWIAEeweNC/IX/l6gsLB+qPvq2UlOgG20Ga7kvt9ljKNeGwmBh
yfQcBkABai0+fUwUbT2J0RSu+YalGR+K/ngE1yxl6r/LWCLuGW4Lv2tRobFwtCAp
rzvxuNMR0/bs+zumJx7PFMAciqBxO0aS/W9vpDrZdVTJGNameDWqCnceq+VwHxOf
dNyIecNBYhqXlefexcsyiIClMLC8Yn33K/txyOEcKwM9B10Ohl4M0NVF+ZhW4khy
GXuTI49hlRC/GuNwGt4agPSom+8g+W2SEeKbEfwT9wKUyiZgZOcWgY2OVQ3N8Cbz
R2SuiCbcUYpPaT45rsJaxxf2mwW46ez+QAxbWOFHm4ujXHIErVz0DcAawtN5PWiB
qsftE5iX91AnOyWM0pgzcid4kjBHHHK8ch9dSKQAQj9tIl0bLGEKXadM11iNfbhc
uQbzKbieCo5m2PKMoU9KeFxv1JkBZuJjaRMU/CF4MHZ1dM5rt5aybh8M1tuu6G+A
5s1F+5Uhi3DFfi2ODnXvsOSRyC+GxuAUc3LHTnTriQdi9UnO3wFwRWo++o8C4I2d
35cvcSfAEU+hd9AVqVRm
=vHrL
-----END PGP SIGNATURE-----
-->
</body>
</html>
