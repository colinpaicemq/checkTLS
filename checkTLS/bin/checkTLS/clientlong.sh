#/usr/lib/jvm/java-11-openjdk-amd64/bin/java  -Djavax.net.debug=none -DpropertyFile="client.properties" -Dfile.encoding=UTF-8 -classpath /home/colinpaice/eclipse-workspace-C/sslJava/bin sslJava.Client

#exit




/usr/lib/jvm/java-11-openjdk-amd64/bin/java -Djavax.net.debug=ssl:handshake -Djava.security.properties=/home/colinpaice/eclipse-workspace-C/sslJava/bin/disabled.properties -Djavax.net.ssl.keyStore=/home/colinpaice/ssl/ssl2/rsarsa.p12 -Djavax.net.ssl.keyStorePassword=password -Djavax.net.ssl.keyStoreType=pkcs12 -Djavax.net.ssl.trustStore=/home/colinpaice/ssl/ssl2/trust.jks -Djavax.net.ssl.trustStorePassword=zpassword -Djavax.net.ssl.trustStoreType=jks -Djdk.tls.client.protocols=TLSv1.2 -Dport=8443 -Dhost="127.0.0.1"  -Dfile.encoding=UTF-8 -classpath /home/colinpaice/eclipse-workspace-C/sslJava/bin sslJava.Client
