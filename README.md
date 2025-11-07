# Scripts SNMP pour Nagios

## Modifications récentes
- Ajout de la possibilité de définir explicitement les protocoles d'authentification et de confidentialité SNMPv3 (MD5/SHA et DES/AES) via les options `-L`, `-A` et `-Y` dans l'ensemble des scripts (`check_snmp_load.pl`, `check_snmp_mem.pl`, `check_snmp_storage.pl`, `check_snmp_uptime.pl`, `check_int_traffic.pl`).
- Validation renforcée des paramètres SNMPv3 : obligation de fournir un mot de passe de confidentialité lorsque `-Y` ou `-L` spécifie un protocole Priv, et vérification que des identifiants SNMPv3 sont fournis avant d'activer ces options.

## Exemples d'usage (SNMPv3 avec protocoles personnalisés)
```bash
# Surveillance de la charge CPU avec authentification SHA et chiffrement AES
./check_snmp_load.pl \
  -H 192.0.2.10 \
  -l nagios-snmpv3 \
  -x "authSecret!" \
  -X "privSecret!" \
  -L sha,aes \
  -w 70,80,90 \
  -c 85,90,95 \
  -T netsl

# Surveillance de l'utilisation mémoire en combinant -A et -Y
./check_snmp_mem.pl \
  -H 192.0.2.11 \
  -l nagios-snmpv3 \
  -x "authSecret!" \
  -X "privSecret!" \
  -A sha \
  -Y aes \
  -w 80 \
  -c 90

# Surveillance du trafic d'interface avec protocole défini en une seule option
./check_int_traffic.pl \
  -H 192.0.2.12 \
  -l nagios-snmpv3 \
  -x "authSecret!" \
  -X "privSecret!" \
  -L sha,aes \
  -i 2 \
  -b 100000000
```

## Exemples de configuration de services Nagios
```nagios
# Définition de commande mutualisée pour SNMPv3
define command{
    command_name    check_snmp_load_v3
    command_line    $USER1$/check_snmp_load.pl -H $HOSTADDRESS$ -l $_HOSTSNMPV3_LOGIN$ -x $_HOSTSNMPV3_AUTHPASS$ -X $_HOSTSNMPV3_PRIVPASS$ -L $_HOSTSNMPV3_AUTHPROTO$,$_HOSTSNMPV3_PRIVPROTO$ -w $ARG1$ -c $ARG2$ -T $ARG3$
}

# Service utilisant les macros hôtes pour sélectionner les protocoles
define service{
    host_name               srv-linux-01
    service_description     CPU Load
    use                     generic-service
    check_command           check_snmp_load_v3!70,80,90!85,90,95!netsl
}

# Commande et service pour la supervision du trafic réseau
define command{
    command_name    check_snmp_int_traffic_v3
    command_line    $USER1$/check_int_traffic.pl -H $HOSTADDRESS$ -l $_HOSTSNMPV3_LOGIN$ -x $_HOSTSNMPV3_AUTHPASS$ -X $_HOSTSNMPV3_PRIVPASS$ -L $_HOSTSNMPV3_AUTHPROTO$,$_HOSTSNMPV3_PRIVPROTO$ -i $ARG1$ -b $ARG2$
}

define service{
    host_name               router-core-01
    service_description     Uplink Gi0/1 Traffic
    use                     generic-service
    check_command           check_snmp_int_traffic_v3!2!100000000
}
```

> 💡 Pensez à définir les macros d'hôte (`_HOSTSNMPV3_LOGIN`, `_HOSTSNMPV3_AUTHPASS`, etc.) ou des variables globales (`$USER1$`, …) correspondant à votre infrastructure afin de centraliser les identifiants SNMPv3 et les protocoles souhaités.
