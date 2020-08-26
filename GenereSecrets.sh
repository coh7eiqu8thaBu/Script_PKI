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
# Script de saisie des 10 mots de passe des agents responsables du
# secret protégeant la clef des authorités de certification
# de la Ville de Marseille
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
# Fonction : Génération d'un mot de passe sécurisé
# Entrées  : Le nombre de caracètres constituant le mot de passe
# Sortie   : Renvoie le mot de passe
#
GenerePassword()
{
  # Utilisation d'une suite pseudo aléatoire de X caractères pouvant contenir 
  #  toutes les lettres de A à Z en majuscule et minuscule, tous les chiffres
  #  et les caractères #([)]-_
  < /dev/urandom tr -dc A-Z-a-z-0-9\#\(\)\[\]_\- | head -c$1
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

# Définition du nombre de clefs privées a générer, chiffrer et séquestrer
# Le valeur est volontairement supérieure au nombre de clefs nécessaires.
# Chaque clef générée sera attribuée à une AC ou à une sous AC différente.
NB_CLEF=8

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
echo "* Script de génération des codes d'authentification pour la protection  *"
echo "* des clefs privées de la PKI de la Ville de Marseille                  *"
echo "*************************************************************************"
echo ""

echo "#########################################################################"
echo "# Saisie des mots de passe du directoire                                #"
echo "#########################################################################"
echo "#"

for ((i=1; i <= NB_DIRECTOIRE; i++)) do
  DIRECTOIRE_ID[$i]="D${i}"
  echo "Personne affectée au n°${i} du directoire,"
  SaisieMDP
  DIRECTOIRE_MDP[$i]=${MDP}
  MDP="`GenerePassword 32`"
  echo "#"
done

echo "#########################################################################"
echo "# Saisie des mots de passe des exploitants                              #"
echo "#########################################################################"
echo "#"

for ((i=1; i <= NB_EXPLOITANT; i++)) do
  EXPLOITANT_ID[$i]="E${i}"
  echo "Personne affectée au n°${i} des exploitants,"
  SaisieMDP
  EXPLOITANT_MDP[$i]=${MDP}
  MDP="`GenerePassword 32`"
  echo "#"
done

# Génération des NB_CLEF codes d'authentification
for ((i=1; i <= NB_CLEF; i++)) do
  CODEDAUTHENTIFICATION[$i]="`GenerePassword 32`"
done

echo "########################################################################"
echo "# Génération des combinaisons des codes d'authentification chiffrés    #"
echo "########################################################################"
echo "#"

# Boucle avec 1 exploitant parmi NB_EXPLOITANT et 2 du directoire parmi x combinaisons
for ((i=1; i <= NB_EXPLOITANT; i++)) do
  for ((j=0; j < ${#COMBINAISON_D[*]}; j++)) do
    # Récupération des valeurs des combinaisons
    INDEX_A=`echo ${COMBINAISON_D[$j]} | cut -c1`
    INDEX_B=`echo ${COMBINAISON_D[$j]} | cut -c2`
    printf "Combinaison : %3s %3s %3s " ${DIRECTOIRE_ID[${INDEX_A}]} ${DIRECTOIRE_ID[${INDEX_B}]} ${EXPLOITANT_ID[${i}]}
    # Création du fichier formaté contenant les codes d'authentifications chiffrés par les mots de passe et les informations permettant leurs usages
    FICHIER_DE_TRAVAIL="CodeDAuthChiffre_${DIRECTOIRE_ID[${INDEX_A}]}_${DIRECTOIRE_ID[${INDEX_B}]}_${EXPLOITANT_ID[${i}]}.txt"
    echo "Page 1/1 - Le `LANG=fr_FR.UTF-8 date "+%A %d %B %Y à %kh%M"`"> ${FICHIER_DE_TRAVAIL}
    echo "" >> ${FICHIER_DE_TRAVAIL}
    echo "##############################################################################" >> ${FICHIER_DE_TRAVAIL}
    echo "#                          Fichier CONFIDENTIEL                              #" >> ${FICHIER_DE_TRAVAIL}
    echo "#                           VILLE DE MARSEILLE                               #" >> ${FICHIER_DE_TRAVAIL}
    printf "#                        Combinaison : %s %s %s                              #\n" ${DIRECTOIRE_ID[${INDEX_A}]} ${DIRECTOIRE_ID[${INDEX_B}]} ${EXPLOITANT_ID[${i}]} >> ${FICHIER_DE_TRAVAIL}
    echo "##############################################################################" >> ${FICHIER_DE_TRAVAIL}
    echo "" >> ${FICHIER_DE_TRAVAIL}
    echo "" >> ${FICHIER_DE_TRAVAIL}
    # Chiffrement
    for ((nb=1; nb <= NB_CLEF; nb++)) do
      echo "--- Début du secret ${nb} chiffré en aes-256-cbc et encodé en base64 ---" >> ${FICHIER_DE_TRAVAIL}
      # Code chiffré stocké dans un fichier temporaire (le chiffrement d'une même donnée ne donne pas le même résultat
      #  car un vecteur d'initialisation aléatoire est utilisé à chaque chiffrement)
      FICHIER_TEMPORAIRE=`mktemp tmp.XXXXXXXXXX`
      echo "${CODEDAUTHENTIFICATION[$nb]}" | openssl aes-256-cbc -e -base64 -k "${DIRECTOIRE_MDP[${INDEX_A}]}${DIRECTOIRE_MDP[${INDEX_B}]}${EXPLOITANT_MDP[${i}]}" > ${FICHIER_TEMPORAIRE}
      cat ${FICHIER_TEMPORAIRE} >> ${FICHIER_DE_TRAVAIL}
      echo "--- Fin du secret ${nb} ---" >> ${FICHIER_DE_TRAVAIL}
      echo -n "MD5 : " >> ${FICHIER_DE_TRAVAIL}
      # MD5 du code chiffré
      cat ${FICHIER_TEMPORAIRE} | openssl dgst -md5 -hex | cut -d' ' -f2 >> ${FICHIER_DE_TRAVAIL}
      # Destruction sécurisée du fichier temporaire
      dd if=/dev/urandom of=${FICHIER_TEMPORAIRE} count=1 bs=512 >/dev/null 2>&1
      rm -f ${FICHIER_TEMPORAIRE}
      echo "" >> ${FICHIER_DE_TRAVAIL}
    done
    echo "" >> ${FICHIER_DE_TRAVAIL}
    # Envoie du fichier sur l'imprimante connectée en 2 exemplaires
    iconv -f UTF-8 -t iso8859-15 ${FICHIER_DE_TRAVAIL} | a2ps -1 -B -q > /dev/null 2>&1
    iconv -f UTF-8 -t iso8859-15 ${FICHIER_DE_TRAVAIL} | a2ps -1 -B -q > /dev/null 2>&1
    echo " --> OK"
  done
done

# Les fichiers résultants ne sont pas supprimmés afin de permettre une
# réimpression en cas de soucis d'impression

# Effacement des mot de passe, au cas où !
for ((i=1; i <= NB_EXPLOITANT; i++)) do
  EXPLOITANT_MDP[${i}]="`GenerePassword 128`"
  EXPLOITANT_MDP[${i}]=""
done
for ((i=1; i <= NB_DIRECTOIRE; i++)) do
  DIRECTOIRE_MDP[${i}]="`GenerePassword 128`"
  DIRECTOIRE_MDP[${i}]=""
done

echo "#"
echo "########################################################################"
echo "#                      Procédure terminée                              #"
echo "########################################################################"
