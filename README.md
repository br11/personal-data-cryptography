# Personal Data Cryptography

## Generating certificates for testing<br/>

openssl req -x509 -newkey rsa:4096 \
        -keyout mykey.pem -out mycert.pem -days 365 
     > key password: changeittoo

openssl pkcs12 -export -in mycert.pem -inkey mykey.pem \
        -name my_test -out mycert-PKCS-12.p12 
     > key password: changeittoo

keytool -importkeystore -deststorepass changeit -destkeystore cacerts \
        -srckeystore mycert-PKCS-12.p12 -srcstoretype PKCS12 
     > key password: changeittoo

openssl req -x509 -newkey rsa:4096 -keyout otherkey.pem \
        -out othercert.pem -days 365
     > key password: changeitaswell
