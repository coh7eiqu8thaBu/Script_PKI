#!/bin/bash
####################################################################
# Auteur : Jérôme Poggi
# Classification : PUBLIQUE
# Historique :
#  Version   : 1.0
#  Date      : 29 Janvier 2013
#  Auditeurs : Pierre Billes et Damien Mauran
#  Commentaires : Version Initiale
####################################################################
# Script de création d'authorité de certification, avec utilisation 
# de secret précédement généré et distribués
####################################################################

####################################################################
# Fonction : Saisie de mot de passe avec vérification de la
#            double saisie, de la non saisie de mot de passe vide
#            et d'une taille au moins égale à 8 caractères
# Entrées  : AUCUNE
# Sortie   : La variable MDP contient le mot de passe
#
SaisieMDP()
{
  # Initialisation des mots de passe à 32 caractères aléatoire
  MDP1="`GenerePassword 32`" # Effacement de la mémoire pour eviter les résidus précédents
  MDP2="`GenerePassword 32`" # Effacement de la mémoire pour eviter les résidus précédents
  until [ ${MDP1} == ${MDP2} ]
  do
    read -s -p "Veuillez saisir votre mot de passe (sans espaces) : " MDP1
    echo
    read -s -p "Veuillez saisir de nouveau votre mot de passe (sans espaces) : " MDP2
    echo
    if [ ${#MDP1} -lt 8 -o ${#MDP2} -lt 8 ]; then
      echo "Erreur dans la saisie du mot de passe, le mot de passe doit au moins contenir 8 caractères !"
      # Effacement des mots de passe
      MDP1="`GenerePassword 32`"
      MDP2="`GenerePassword 32`"
    fi
    if [ "${MDP1}" != "${MDP2}" ]; then
      echo "Erreur dans la saisie du mot de passe, les deux mots de passe ne sont pas identiques !"
    else
      # Remplissage de la variable de sortie
      MDP=${MDP1}
    fi
  done
}

####################################################################
# Fonction : Attend un caractère tant que ce caractère n'est pas 
#            dans une liste passée en entrée de la fonction
# Entrées  : La liste des caractères autorisés
#              (exemple : SaisieChoix "12345AByz")
# Sortie   : La variable CHOIX contient le caractère tapé 
#              en majuscule
#
SaisieChoix()
{
  CHOIX="Bidon"
  CHOIX_POSSIBLE="${1^^*}" # Mise en majuscule
  until [[ ${CHOIX} =~ ^[${CHOIX_POSSIBLE}]$ ]]; do
    read -n 1 -p "> " CHOIX
    # Passage en majuscule
    CHOIX=${CHOIX^^*}
    echo
  done
}

####################################################################
# Fonction : Génération d'un mot de passe sécurisé
# Entrées  : Le nombre de caracètres constituant le mot de passe
# Sortie   : Renvoie le mot de passe
#
GenerePassword()
{
  # Utilisation d'une suite pseudo aléatoire de X caractères pouvant contenir 
  #  toutes les lettres de A à Z en majuscule et minuscule, tous les chiffres
  #  et les caractères #([)]-_
  CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
  CheckMD5 ${FICHIERS[${ID_HEAD}]} ${MD5[${ID_HEAD}]}
  < /dev/urandom tr -dc A-Z-a-z-0-9\#\(\)\[\]_\- | ${FICHIERS[${ID_HEAD}]} -c$1
}

####################################################################
# Fonction : Demande la saisie du code d'authentification chiffré.
#            Une fois saisi, elle affiche le MD5 de la saisie pour
#             vérification et sort du programme si la saisie n'est
#             pas validée.
# Entrées  : Le numéro d'index du code à demander
#            Une chaine de caractères contenant la combinaison des
#              agents (exemple : "D1 D3 E2")
# Sortie   : Les variables CODEDAUTHENTIFICATION_CHIFFRE_L1 et
#             CODEDAUTHENTIFICATION_CHIFFRE_L2 contiennent le texte
#             saisi
#
SaisieCodeAuthChiffre()
{
  SAISIE_OK="NON"
  while [ "${SAISIE_OK}" != "Oui" ]
  do
    echo "Veuillez saisir le secret chiffré de l'AC '${LISTE_CAS[${1}]}' pour la combinaison ${2}."
    echo "Ce code se présente sous la forme suivante :"
    echo "--- Début du secret x chiffré en aes-256-cbc et encodé en base64 ---
U2FsdGVkX1/c7OdrjKzrBgK1rqFEsgkz8AZsYp3dCkQN4pLxrfc8ar+lqTyAZbvF
ryfMytFlwIdGB3I/VEcYAN==
--- Fin du secret x ---
MD5 : a62ac503a94621a88ed54823ee9def25
#"
    read -p "Veuillez saisir la première ligne : " CACL1
    read -p "Veuillez saisir la deuxième ligne : " CACL2

    echo "#"
    echo "L'empreinte MD5 des données que vous venez de saisir est : "
    CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
    CheckMD5 ${FICHIERS[${ID_ECHO}]} ${MD5[${ID_ECHO}]}
    CheckMD5 ${FICHIERS[${ID_OPENSSL}]} ${MD5[${ID_OPENSSL}]}
    (${FICHIERS[${ID_ECHO}]} ${CACL1}; ${FICHIERS[${ID_ECHO}]} ${CACL2}) | ${FICHIERS[${ID_OPENSSL}]} dgst -md5 -hex
    echo "Est-elle conforme ? (o/n)"
    SaisieChoix "ONY"
    if [ "${CHOIX}" == "N" ]; then
      echo "L'empreinte MD5 ne correspondant pas, il est impossible de l'utiliser."
      echo "Voulez-vous essayer de la ressaisir ? (o/n)"
      SaisieChoix "ONY"
      if [ "${CHOIX}" == "N" ]; then
        echo "Veuillez relancer la procédure soit en ressaisissant le code chiffré soit en changeant de combinaison !"
        exit 255
      else
        echo ""
      fi
    else
      SAISIE_OK="Oui"
    fi
  done
  CODEDAUTHENTIFICATION_CHIFFRE_L1=${CACL1}
  CODEDAUTHENTIFICATION_CHIFFRE_L2=${CACL2}

  # Vérification des empreintes des binaires utilsés 
  CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
  CheckMD5 ${FICHIERS[${ID_ECHO}]} ${MD5[${ID_ECHO}]}
  CheckMD5 ${FICHIERS[${ID_OPENSSL}]} ${MD5[${ID_OPENSSL}]}
  # Vérification de la validité du code d'authenfication
  (${FICHIERS[${ID_ECHO}]} ${CODEDAUTHENTIFICATION_CHIFFRE_L1}; ${FICHIERS[${ID_ECHO}]} ${CODEDAUTHENTIFICATION_CHIFFRE_L2}) | ${FICHIERS[${ID_OPENSSL}]} aes-256-cbc -d -base64 -k "${DIRECTOIRE_MDP1}${DIRECTOIRE_MDP2}${EXPLOITANT_MDP}" >/dev/null 2>&1
  ret=$?
  if [ $ret -ne 0 ]; then
    echo "ERREUR !!!"
    echo "Les mots de passe fournis ne permettent pas de déchiffrer le code d'authentification."
    echo "Au moins un des 3 mots de passe saisis est incorrect."
    exit 253
  fi
}

####################################################################
# Fonction : Vérifie si l'empreinte MD5 d'un fichier est conforme
#            et si ce n'est pas le cas, le programe est arrêté
# Entrées  : Le fichier à tester et son empreinte
#              (exemple : CheckMD5 /etc/motd 46b548929c88cad7f6bb8eae75ba298e)
# Sortie   : Aucune
#
CheckMD5()
{
  if [ "`/bin/cat ${1} | /usr/bin/openssl dgst -md5 -hex | /bin/cut -d' ' -f2`" != "${2}" ]
  then
    echo "ERREUR !!!"
    echo "L'empreinte MD5 du fichier '${1}' n'est pas conforme à celle attendue."
    exit 247
  fi
}

####################################################################
# Variables globales

# Nombre d'agents du directoire
NB_DIRECTOIRE=6
# Définition des combinaisons 2 parmis 6 du directoire
COMBINAISON_D=( "12" "13" "14" "15" "16"\
                "23" "24" "25" "26" \
                "34" "35" "36" \
                "45" "46" \
                "56" )
# Nombre d'agents exploitants
NB_EXPLOITANT=4
# Fichiers dont l'empreinte est à tester
FICHIERS=("${1}/bin/java" "${2}/dist/ejbca-ejb-cli/ejbca-ejb-cli.jar" \
          "/bin/bash" "/usr/bin/head" "/bin/echo" "/usr/bin/openssl" \
          "/bin/cat" "/bin/cut" "/bin/ls" "/bin/sed" "/bin/mktemp" \
          "/bin/rm" "/bin/grep" "/bin/sleep")
# Chargement des ID des fichiers
ID_JAVA=0
ID_JAR=1
ID_BASH=2
ID_HEAD=3
ID_ECHO=4
ID_OPENSSL=5
ID_CAT=6
ID_CUT=7
ID_LS=8
ID_SED=9
ID_MKTEMP=10
ID_RM=11
ID_GREP=12
ID_SLEEP=13

# Identifiant des AC pour l'EJBCA
LISTE_CAS=("Ville_de_Marseille_-_Autorite_Racine" 
           "Ville_de_Marseille_-_Sous-Autorite_d_Infrastructure" \
           "Ville_de_Marseille_-_Sous-Autorite_Personnel")
LISTE_CAS_DN=("CN=Ville de Marseille - Autorite Racine,OU=0002 21130055300016,O=Ville de Marseille,L=Marseille,ST=PACA,C=FR" \
              "CN=Ville de Marseille - Sous-Autorite Infrastructure,OU=0002 21130055300016,O=Ville de Marseille,L=Marseille,ST=PACA,C=FR" \
              "CN=Ville de Marseille - Sous-Autorite Personnel,OU=0002 21130055300016,O=Ville de Marseille,L=Marseille,ST=PACA,C=FR")

####################################################################
# Début du programme                                               #
####################################################################

clear
echo "*************************************************************************"
echo "* AVEZ-VOUS VERIFIE L'EMPREINTE MD5 DU SCRIPT (oui/NON) ?               *"
echo "*************************************************************************"
read -p "Veuillez saisir OUI en toute lettre pour continuer : " rep
if [ "${rep^^*}" != "OUI" ]; then
  echo "Fin du programme !"
  exit 1
fi

clear

echo "*************************************************************************"
echo "* Script de création des autorités de certifications avec les mots de   *"
echo "* passe de 2 agents du Directoire et de 1 exploitant                    *"
echo "*************************************************************************"
echo ""

# Ce script doit être lancé en tant que JBOSS sinon on quitte le programme
if [ "$USER" != "jboss" ]; then
  echo "ERREUR !!!"
  echo "Ce programme doit être lancé sous l'identité 'jboss'."
  echo "Veuillez basculer sur la bonne identité puis relancer ce script."
  exit 254
fi

# Vérification des paramètres
if [ "$1" = "" -o "$2" = "" ] ; then
	echo "Usage: CreationAC_VDM.sh répertoire_java répertoire_jar"
	exit 248
fi

echo "########################################################################"
echo "# Contrôle des programmes appelés                                      #"
echo "########################################################################"
echo "#"
echo "Veuillez vérifier que les empreintes MD5 suivantes sont conformes aux"
echo " empreintes validées lors de l'audit de code."
echo "#"

# Récupération des empreintes MD5 des fichiers
for ((i=0; i<${#FICHIERS[*]}; i++)) do
  MD5[$i]=`${FICHIERS[${ID_CAT}]} ${FICHIERS[${i}]} | ${FICHIERS[${ID_OPENSSL}]} dgst -md5 -hex | ${FICHIERS[${ID_CUT}]} -d' ' -f2`
  ${FICHIERS[${ID_LS}]} -al ${FICHIERS[${i}]}
  echo ${MD5[${i}]}
  echo "#"
done

echo "Est-ce que ces informations sont conformes aux attentes ? (o/n)"
SaisieChoix "ONY"
if [ "${CHOIX}" == "N" ]; then
  echo "Les fichiers externes à ce script ne sont pas conformes aux attentes."
  echo "La confidentialité des secrets ne peut pas être garantie."
  exit 249
fi

echo "#"
echo "########################################################################"
echo "# Choix des agents du Directoire et de l'Exploitant                    #"
echo "########################################################################"
echo "#"
echo "Veuillez saisir le numéro d'ordre du premier agent du Directoire :"
LISTE_CHOIX=""
for ((i=1; i <= NB_DIRECTOIRE; i++)) do
  DIRECTOIRE_ID[$i]="D${i}"
  echo "$i - ${DIRECTOIRE_ID[$i]}"
  LISTE_CHOIX="${LISTE_CHOIX}${i}"
done
SaisieChoix ${LISTE_CHOIX}
AGENT_D1=${CHOIX}
echo "Choix : ${DIRECTOIRE_ID[${AGENT_D1}]}"
echo "#"

echo "Veuillez saisir le numéro d'ordre du deuxième agent du Directoire :"
LISTE_CHOIX=""
for ((i=1; i <= NB_DIRECTOIRE; i++)) do
  if [ $i != ${AGENT_D1} ]; then
    # on ne re-propose pas le premier agent
    echo "$i - ${DIRECTOIRE_ID[$i]}"
    LISTE_CHOIX="${LISTE_CHOIX}${i}"
  fi
done
SaisieChoix ${LISTE_CHOIX}
AGENT_D2=${CHOIX}
echo "Choix : ${DIRECTOIRE_ID[${AGENT_D2}]}"
echo "#"

echo "Veuillez saisir le numéro de l'agent exploitant :"
LISTE_CHOIX=""
for ((i=1; i <= NB_EXPLOITANT; i++)) do
  EXPLOITANT_ID[$i]="E${i}"
  echo "$i - ${EXPLOITANT_ID[$i]}"
  LISTE_CHOIX="${LISTE_CHOIX}${i}"
done
SaisieChoix ${LISTE_CHOIX}
AGENT_E=${CHOIX}
echo "Choix : ${EXPLOITANT_ID[${AGENT_E}]}"
echo "#"

# Recherche de la combinaison normalisée
COMBINAISON=""
for i in "${AGENT_D1}${AGENT_D2}" "${AGENT_D2}${AGENT_D1}" ; do
  for ((j=0; j < ${#COMBINAISON_D[*]}; j++)) do
    if [ "${i}" == "${COMBINAISON_D[${j}]}" ]; then COMBINAISON=${i}; fi
  done
done

if [ "${COMBINAISON}" == "" ]; then
  echo "ERREUR - La combinaison normalisée n'a pas été trouvée !"
  exit 252
fi

# Affichage du quorum validé
CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
CheckMD5 ${FICHIERS[${ID_ECHO}]} ${MD5[${ID_ECHO}]}
CheckMD5 ${FICHIERS[${ID_CUT}]} ${MD5[${ID_CUT}]}
INDEX_A=`${FICHIERS[${ID_ECHO}]} ${COMBINAISON} | ${FICHIERS[${ID_CUT}]} -c1`
CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
CheckMD5 ${FICHIERS[${ID_ECHO}]} ${MD5[${ID_ECHO}]}
CheckMD5 ${FICHIERS[${ID_CUT}]} ${MD5[${ID_CUT}]}
INDEX_B=`${FICHIERS[${ID_ECHO}]} ${COMBINAISON} | ${FICHIERS[${ID_CUT}]} -c2`
echo "La combinaison normalisée est : ${DIRECTOIRE_ID[${INDEX_A}]} ${DIRECTOIRE_ID[${INDEX_B}]} ${EXPLOITANT_ID[${AGENT_E}]}"

echo "#"
echo "################################################################################"
echo "# Saisie des mots de passe permettant de déchiffrer le code d'authentification #"
echo "################################################################################"
echo "#"

echo " Personne correspondant au code ${DIRECTOIRE_ID[${INDEX_A}]} du Directoire,"
SaisieMDP
DIRECTOIRE_MDP1=${MDP}
echo "#"
echo " Personne correspondant au code ${DIRECTOIRE_ID[${INDEX_B}]} du Directoire,"
SaisieMDP
DIRECTOIRE_MDP2=${MDP}
echo "#"
echo " Personne correspondant au code ${EXPLOITANT_ID[${AGENT_E}]} des exploitants,"
SaisieMDP
EXPLOITANT_MDP=${MDP}

echo "#"

CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
CheckMD5 ${FICHIERS[${ID_JAVA}]} ${MD5[${ID_JAVA}]}
CheckMD5 ${FICHIERS[${ID_JAR}]} ${MD5[${ID_JAR}]}
CheckMD5 ${FICHIERS[${ID_GREP}]} ${MD5[${ID_GREP}]}
CheckMD5 ${FICHIERS[${ID_CUT}]} ${MD5[${ID_CUT}]}
CAID_AC_RACINE=`${FICHIERS[${ID_JAVA}]} -jar ${FICHIERS[${ID_JAR}]} ca info ${LISTE_CAS[0]} 2>/dev/null | ${FICHIERS[${ID_GREP}]} '^CA ID:' | ${FICHIERS[${ID_CUT}]} -c8-`
if [ "${CAID_AC_RACINE}" = "" ]
then

  echo "########################################################################"
  echo "# Récupération du Code d'authentification chiffré pour l'AC Racine     #"
  echo "########################################################################"
  echo "#"

  SaisieCodeAuthChiffre 0 "${DIRECTOIRE_ID[${INDEX_A}]} ${DIRECTOIRE_ID[${INDEX_B}]} ${EXPLOITANT_ID[${AGENT_E}]}"
  
  echo "#"
  echo "########################################################################"
  echo "# Création de l'Autorité de Certifications Racine                      #"
  echo "########################################################################"
  
  echo "#"
  echo "Libélé de l'AC : ${LISTE_CAS[0]}"
  echo "DN de l'AC : ${LISTE_CAS_DN[0]}"
  echo "#"
  echo " ATTENTION - ATTENTION - ATTENTION - ATTENTION"
  echo "Voulez-vous vraiment lancer la procédure de création de l'autorité de certification RACINE ?"
  read -p "Veuillez saisir OUI en toute lettre pour continuer : " rep
  if [ "${rep^^*}" != "OUI" ]; then
    echo "Fin du programme !"
    exit 1
  fi
  
  echo "#"
  # Vérification des empreintes des binaires utilsés 
  CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
  CheckMD5 ${FICHIERS[${ID_JAVA}]} ${MD5[${ID_JAVA}]}
  CheckMD5 ${FICHIERS[${ID_JAR}]} ${MD5[${ID_JAR}]}
  CheckMD5 ${FICHIERS[${ID_ECHO}]} ${MD5[${ID_ECHO}]}
  CheckMD5 ${FICHIERS[${ID_OPENSSL}]} ${MD5[${ID_OPENSSL}]}
  # Lancement de la commande en batch à la PKI EJCBA en direct
  ${FICHIERS[${ID_JAVA}]} -jar ${FICHIERS[${ID_JAR}]} ca init \
  "${LISTE_CAS[0]}" "${LISTE_CAS_DN[0]}" \
  soft \
  `(${FICHIERS[${ID_ECHO}]} ${CODEDAUTHENTIFICATION_CHIFFRE_L1}; ${FICHIERS[${ID_ECHO}]} ${CODEDAUTHENTIFICATION_CHIFFRE_L2}) | ${FICHIERS[${ID_OPENSSL}]} aes-256-cbc -d -base64 -k "${DIRECTOIRE_MDP1}${DIRECTOIRE_MDP2}${EXPLOITANT_MDP}"` \
  4096 RSA 7306 \
  "2.5.29.32.0 http://pki.mairie-marseille.fr/PC/" \
  "SHA256WithRSA" -certprofile CP_VdM_ROOTCA 2>/dev/null
  
  CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
  CheckMD5 ${FICHIERS[${ID_SLEEP}]} ${MD5[${ID_SLEEP}]}
  ${FICHIERS[${ID_SLEEP}]} 10 # on attend que tout soit stabilisé
  CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
  CheckMD5 ${FICHIERS[${ID_JAVA}]} ${MD5[${ID_JAVA}]}
  CheckMD5 ${FICHIERS[${ID_JAR}]} ${MD5[${ID_JAR}]}
  CheckMD5 ${FICHIERS[${ID_GREP}]} ${MD5[${ID_GREP}]}
  CheckMD5 ${FICHIERS[${ID_CUT}]} ${MD5[${ID_CUT}]}
  CAID_AC_RACINE=`${FICHIERS[${ID_JAVA}]} -jar ${FICHIERS[${ID_JAR}]} ca info "${LISTE_CAS[0]}" | ${FICHIERS[${ID_GREP}]} '^CA ID:' | ${FICHIERS[${ID_CUT}]} -c8-`
  echo "#"
  if [ "${CAID_AC_RACINE}" = "" ]
  then
    echo "ERREUR !!!"
    echo "La création de l'autorité ne s'est pas faite avec succès."
    echo "Veuillez vérifier et diagnostiquer manuellement le problème."
    exit 251
  else
    echo "Création de la CA ("${LISTE_CAS_DN[0]}") effectuée avec succès."
    echo "Veuillez maintenant vous connecter sur l'interface d'administration"
    echo "  de l'IGC EJBCA et définir les paramètres de :"
    echo "  - Directives : tout doit être coché"
    echo "  - \"Codage PrintableString pour les attributs du DN\" à \"Utiliser\""
    echo "  - Point de distribution de LCR par défaut et le nom de l'émetteur"
    echo "  - Les périodes de validité de la LCR"
    echo "  - Adresse du service OCSP par défaut"
    echo "Une fois ces opérations effectuées, veuillez relancer ce script pour créer les AC subordonnées."
    exit 0
  fi
else
  # CREATION des AC Subordonnées
  CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
  CheckMD5 ${FICHIERS[${ID_JAVA}]} ${MD5[${ID_JAVA}]}
  CheckMD5 ${FICHIERS[${ID_JAR}]} ${MD5[${ID_JAR}]}
  CheckMD5 ${FICHIERS[${ID_GREP}]} ${MD5[${ID_GREP}]}
  CheckMD5 ${FICHIERS[${ID_CUT}]} ${MD5[${ID_CUT}]}
  CAID_AC_INFRA=`${FICHIERS[${ID_JAVA}]} -jar ${FICHIERS[${ID_JAR}]} ca info ${LISTE_CAS[1]} 2>/dev/null | ${FICHIERS[${ID_GREP}]} '^CA ID:' | ${FICHIERS[${ID_CUT}]} -c8-`
  if [ "${CAID_AC_INFRA}" = "" ]
  then

    echo "###########################################################################"
    echo "# Récupération du Code d'authentification chiffré pour l'AC Infrastrucure #"
    echo "###########################################################################"
    echo "#"
    echo "Libélé de l'AC : ${LISTE_CAS[1]}"
    echo "DN de l'AC : ${LISTE_CAS_DN[1]}"
  
    SaisieCodeAuthChiffre 1 "${DIRECTOIRE_ID[${INDEX_A}]} ${DIRECTOIRE_ID[${INDEX_B}]} ${EXPLOITANT_ID[${AGENT_E}]}"
    
    echo "#"
    echo "########################################################################"
    echo "# Création de l'Autorité de Certifications d'infrastructure            #"
    echo "########################################################################"
    
    echo "#"
    echo " ATTENTION - ATTENTION - ATTENTION - ATTENTION"
    echo "Voulez-vous vraiment lancer la procédure de création de l'autorité de certification d'INFRASTRUCTURE ?"
    read -p "Veuillez saisir OUI en toute lettre pour continuer : " rep
    if [ "${rep^^*}" != "OUI" ]; then
      echo "Fin du programme !"
      exit 1
    fi
  
    echo "#"
    # Vérification des empreintes des binaires utilsés 
    CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
    CheckMD5 ${FICHIERS[${ID_JAVA}]} ${MD5[${ID_JAVA}]}
    CheckMD5 ${FICHIERS[${ID_JAR}]} ${MD5[${ID_JAR}]}
    CheckMD5 ${FICHIERS[${ID_ECHO}]} ${MD5[${ID_ECHO}]}
    CheckMD5 ${FICHIERS[${ID_OPENSSL}]} ${MD5[${ID_OPENSSL}]}
    # Lancement de la commande en batch à la PKI EJCBA en direct
    ${FICHIERS[${ID_JAVA}]} -jar ${FICHIERS[${ID_JAR}]} ca init \
    "${LISTE_CAS[1]}" "${LISTE_CAS_DN[1]}" \
    soft \
    `(${FICHIERS[${ID_ECHO}]} ${CODEDAUTHENTIFICATION_CHIFFRE_L1}; ${FICHIERS[${ID_ECHO}]} ${CODEDAUTHENTIFICATION_CHIFFRE_L2}) | ${FICHIERS[${ID_OPENSSL}]} aes-256-cbc -d -base64 -k "${DIRECTOIRE_MDP1}${DIRECTOIRE_MDP2}${EXPLOITANT_MDP}"` \
    4096 RSA 3653 \
    "2.5.29.32.0 http://pki.mairie-marseille.fr/PC/" \
    "SHA256WithRSA" -certprofile CP_VdM_SUBCA \
    null ${CAID_AC_RACINE} 2>/dev/null
  
    CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
    CheckMD5 ${FICHIERS[${ID_SLEEP}]} ${MD5[${ID_SLEEP}]}
    ${FICHIERS[${ID_SLEEP}]} 10 # on attend que tout soit stabilisé
    CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
    CheckMD5 ${FICHIERS[${ID_JAVA}]} ${MD5[${ID_JAVA}]}
    CheckMD5 ${FICHIERS[${ID_JAR}]} ${MD5[${ID_JAR}]}
    CheckMD5 ${FICHIERS[${ID_GREP}]} ${MD5[${ID_GREP}]}
    CheckMD5 ${FICHIERS[${ID_CUT}]} ${MD5[${ID_CUT}]}
    CAID_AC_INFRA=`${FICHIERS[${ID_JAVA}]} -jar ${FICHIERS[${ID_JAR}]} ca info ${LISTE_CAS[1]} | ${FICHIERS[${ID_GREP}]} '^CA ID:' | ${FICHIERS[${ID_CUT}]} -c8-`
    echo "#"
    if [ "${CAID_AC_INFRA}" = "" ]
    then
      echo "ERREUR !!!"
      echo "La création de l'autorité ne s'est pas faite avec succès."
      echo "Veuillez vérifier et diagnostiquer manuellement le problème."
      exit 250
    else
      echo "Création de la Sous CA ("${LISTE_CAS_DN[1]}") effectuée avec succès."
      echo "Veuillez vous connecter sur l'interface d'administration"
      echo "  de l'IGC EJBCA et définir les paramètres de :"
      echo "  - Directives : tout doit être coché"
      echo "  - \"Codage PrintableString pour les attributs du DN\" à \"Utiliser\""
      echo "  - Point de distribution de LCR par défaut et le nom de l'émetteur"
      echo "  - Les périodes de validité de la LCR"
      echo "#"
    fi
  else
    echo "ATTENTION !!!"
    echo "L'autorité de certification d'infrastructure est déjà présente."
    echo "#"
  fi

  # CREATION des AC Subordonnées
  CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
  CheckMD5 ${FICHIERS[${ID_JAVA}]} ${MD5[${ID_JAVA}]}
  CheckMD5 ${FICHIERS[${ID_JAR}]} ${MD5[${ID_JAR}]}
  CheckMD5 ${FICHIERS[${ID_GREP}]} ${MD5[${ID_GREP}]}
  CheckMD5 ${FICHIERS[${ID_CUT}]} ${MD5[${ID_CUT}]}
  CAID_AC_PERSONNEL=`${FICHIERS[${ID_JAVA}]} -jar ${FICHIERS[${ID_JAR}]} ca info ${LISTE_CAS[2]} 2>/dev/null | ${FICHIERS[${ID_GREP}]} '^CA ID:' | ${FICHIERS[${ID_CUT}]} -c8-`
  if [ "${CAID_AC_PERSONNEL}" = "" ]
  then

    echo "########################################################################"
    echo "# Récupération du Code d'authentification chiffré pour l'AC Personnel  #"
    echo "########################################################################"
    echo "#"
    echo "Libélé de l'AC : ${LISTE_CAS[2]}"
    echo "DN de l'AC : ${LISTE_CAS_DN[2]}"
  
    SaisieCodeAuthChiffre 2 "${DIRECTOIRE_ID[${INDEX_A}]} ${DIRECTOIRE_ID[${INDEX_B}]} ${EXPLOITANT_ID[${AGENT_E}]}"
    
    echo "#"
    echo "########################################################################"
    echo "# Création de l'Autorité de Certifications pour le Personnel           #"
    echo "########################################################################"
    
    echo "#"
    echo " ATTENTION - ATTENTION - ATTENTION - ATTENTION"
    echo "Voulez-vous vraiment lancer la procédure de création de l'autorité de certification pour le Personnel ?"
    read -p "Veuillez saisir OUI en toute lettre pour continuer : " rep
    if [ "${rep^^*}" != "OUI" ]; then
      echo "Fin du programme !"
      exit 1
    fi
  
    echo "#"
    # Vérification des empreintes des binaires utilsés 
    CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
    CheckMD5 ${FICHIERS[${ID_JAVA}]} ${MD5[${ID_JAVA}]}
    CheckMD5 ${FICHIERS[${ID_JAR}]} ${MD5[${ID_JAR}]}
    CheckMD5 ${FICHIERS[${ID_ECHO}]} ${MD5[${ID_ECHO}]}
    CheckMD5 ${FICHIERS[${ID_OPENSSL}]} ${MD5[${ID_OPENSSL}]}
    # Lancement de la commande en batch à la PKI EJCBA en direct
    ${FICHIERS[${ID_JAVA}]} -jar ${FICHIERS[${ID_JAR}]} ca init \
    "${LISTE_CAS[2]}" "${LISTE_CAS_DN[2]}" \
    soft \
    `(${FICHIERS[${ID_ECHO}]} ${CODEDAUTHENTIFICATION_CHIFFRE_L1}; ${FICHIERS[${ID_ECHO}]} ${CODEDAUTHENTIFICATION_CHIFFRE_L2}) | ${FICHIERS[${ID_OPENSSL}]} aes-256-cbc -d -base64 -k "${DIRECTOIRE_MDP1}${DIRECTOIRE_MDP2}${EXPLOITANT_MDP}"` \
    4096 RSA 3653 \
    "2.5.29.32.0 http://pki.mairie-marseille.fr/PC/" \
    "SHA256WithRSA" -certprofile CP_VdM_SUBCA \
    null ${CAID_AC_RACINE} 2>/dev/null
  
    CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
    CheckMD5 ${FICHIERS[${ID_SLEEP}]} ${MD5[${ID_SLEEP}]}
    ${FICHIERS[${ID_SLEEP}]} 10 # on attend que tout soit stabilisé
    CheckMD5 ${FICHIERS[${ID_BASH}]} ${MD5[${ID_BASH}]}
    CheckMD5 ${FICHIERS[${ID_JAVA}]} ${MD5[${ID_JAVA}]}
    CheckMD5 ${FICHIERS[${ID_JAR}]} ${MD5[${ID_JAR}]}
    CheckMD5 ${FICHIERS[${ID_GREP}]} ${MD5[${ID_GREP}]}
    CheckMD5 ${FICHIERS[${ID_CUT}]} ${MD5[${ID_CUT}]}
    CAID_AC_PERSONNEL=`${FICHIERS[${ID_JAVA}]} -jar ${FICHIERS[${ID_JAR}]} ca info ${LISTE_CAS[2]} | ${FICHIERS[${ID_GREP}]} '^CA ID:' | ${FICHIERS[${ID_CUT}]} -c8-`
    echo "#"
    if [ "${CAID_AC_PERSONNEL}" = "" ]
    then
      echo "ERREUR !!!"
      echo "La création de l'autorité ne s'est pas faite avec succès."
      echo "Veuillez vérifier et diagnostiquer manuellement le problème."
      exit 250
    else
      echo "Création de la Sous CA ("${LISTE_CAS_DN[2]}") effectuée avec succès."
      echo "Veuillez vous connecter sur l'interface d'administration"
      echo "  de l'IGC EJBCA et définir les paramètres de :"
      echo "  - Directives : tout doit être coché"
      echo "  - \"Codage PrintableString pour les attributs du DN\" à \"Utiliser\""
      echo "  - Point de distribution de LCR par défaut et le nom de l'émetteur"
      echo "  - Les périodes de validité de la LCR"
      echo "#"
    fi
  else
    echo "ATTENTION !!!"
    echo "L'autorité de certification pour le personnel est déjà présente."
    echo "#"
  fi
fi

# Effacement sécurisé des variables temporaires
CODEDAUTHENTIFICATION_CHIFFRE_L1="`GenerePassword 128`"
CODEDAUTHENTIFICATION_CHIFFRE_L2="`GenerePassword 128`"
DIRECTOIRE_MDP1="`GenerePassword 128`"
DIRECTOIRE_MDP2="`GenerePassword 128`"
EXPLOITANT_MDP="`GenerePassword 128`"
