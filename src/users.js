const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { postgresConfigure } = require("./database");

const codesVerification = new Map();

function normaliserNumero(numero) {
    let resultat = String(numero || "").trim().replace(/[\s().-]/g, "");

    if (resultat.startsWith("+")) {
        resultat = resultat.slice(1);
    }

    if (resultat.startsWith("00")) {
        resultat = resultat.slice(2);
    }

    if (resultat.startsWith("0")) {
        resultat = "243" + resultat.slice(1);
    }

    return resultat;
}

function numeroValide(numero) {
    return /^243\d{9}$/.test(normaliserNumero(numero));
}

function convertirUtilisateur(ligne) {
    if (!ligne) return null;

    return {
        id: ligne.id,
        identifiant: ligne.identifiant,
        nom: ligne.nom,
        numero: ligne.numero,
        motDePasseHash: ligne.motDePasseHash,
        creeLe: ligne.creeLe
    };
}

const COLONNES_UTILISATEUR = `
    id,
    identifiant,
    nom,
    numero,
    mot_de_passe_hash AS "motDePasseHash",
    cree_le AS "creeLe"
`;

function genererIdentifiant() {
    return "JJM-" + crypto.randomBytes(4).toString("hex").toUpperCase();
}

async function creerUtilisateur(nom, numero, motDePasse) {
    const nomNettoye = String(nom || "").trim();
    const numeroNormalise = normaliserNumero(numero);
    const motDePasseTexte = String(motDePasse || "");

    if (!nomNettoye) {
        throw new Error("Le nom est obligatoire.");
    }

    if (!numeroValide(numeroNormalise)) {
        throw new Error("Numéro de téléphone invalide.");
    }

    if (!motDePasseTexte) {
        throw new Error("Le mot de passe est obligatoire.");
    }

    const db = postgresConfigure();

    const existant = await db.query(
        "SELECT id FROM utilisateurs WHERE numero = $1 LIMIT 1",
        [numeroNormalise]
    );

    if (existant.rows.length > 0) {
        throw new Error("Ce numéro est déjà enregistré.");
    }

    const motDePasseHash = await bcrypt.hash(motDePasseTexte, 12);

    for (let tentative = 0; tentative < 3; tentative++) {
        const utilisateur = {
            id: crypto.randomUUID(),
            identifiant: genererIdentifiant(),
            nom: nomNettoye,
            numero: numeroNormalise,
            motDePasseHash
        };

        try {
            const resultat = await db.query(
                `INSERT INTO utilisateurs
                    (id, identifiant, nom, numero, mot_de_passe_hash)
                 VALUES ($1, $2, $3, $4, $5)
                 RETURNING ${COLONNES_UTILISATEUR}`,
                [
                    utilisateur.id,
                    utilisateur.identifiant,
                    utilisateur.nom,
                    utilisateur.numero,
                    utilisateur.motDePasseHash
                ]
            );

            return convertirUtilisateur(resultat.rows[0]);
        } catch (erreur) {
            if (erreur.code === "23505") {
                if (erreur.constraint === "utilisateurs_numero_key") {
                    throw new Error("Ce numéro est déjà enregistré.");
                }

                if (tentative < 2) continue;
            }

            throw erreur;
        }
    }

    throw new Error("Impossible de créer le compte. Réessaie.");
}

async function verifierConnexion(numero, motDePasse) {
    const numeroNormalise = normaliserNumero(numero);
    const db = postgresConfigure();

    const resultat = await db.query(
        `SELECT ${COLONNES_UTILISATEUR}
         FROM utilisateurs
         WHERE numero = $1
         LIMIT 1`,
        [numeroNormalise]
    );

    const utilisateur = convertirUtilisateur(resultat.rows[0]);

    if (!utilisateur) return null;

    const valide = await bcrypt.compare(
        String(motDePasse || ""),
        utilisateur.motDePasseHash
    );

    return valide ? utilisateur : null;
}

function creerCodeVerification(numero) {
    const numeroNormalise = normaliserNumero(numero);
    const code = String(crypto.randomInt(100000, 1000000));

    codesVerification.set(numeroNormalise, {
        code,
        expireLe: Date.now() + 5 * 60 * 1000,
        tentatives: 0
    });

    return code;
}

function verifierCodeVerification(numero, code) {
    const numeroNormalise = normaliserNumero(numero);
    const entree = codesVerification.get(numeroNormalise);

    if (!entree) return false;

    if (Date.now() > entree.expireLe || entree.tentatives >= 5) {
        codesVerification.delete(numeroNormalise);
        return false;
    }

    entree.tentatives++;

    if (entree.code !== String(code || "").trim()) {
        if (entree.tentatives >= 5) {
            codesVerification.delete(numeroNormalise);
        }
        return false;
    }

    codesVerification.delete(numeroNormalise);
    return true;
}

async function listerUtilisateursJJM(identifiantExclu) {
    const db = postgresConfigure();

    const resultat = await db.query(
        `SELECT identifiant, nom, numero
         FROM utilisateurs
         WHERE identifiant <> $1
         ORDER BY nom ASC`,
        [String(identifiantExclu || "")]
    );

    return resultat.rows;
}

async function rechercherUtilisateursJJM(terme, identifiantExclu) {
    const recherche = String(terme || "").trim();

    if (recherche.length < 2) return [];

    const db = postgresConfigure();
    const chiffres = recherche.replace(/\D/g, "");
    const resultat = await db.query(
        `SELECT identifiant, nom, numero
         FROM utilisateurs
         WHERE identifiant <> $1
           AND (
               nom ILIKE $2
               OR identifiant ILIKE $2
               OR ($3 <> '' AND numero LIKE $4)
           )
         ORDER BY nom ASC
         LIMIT 30`,
        [
            String(identifiantExclu || ""),
            "%" + recherche + "%",
            chiffres,
            "%" + chiffres + "%"
        ]
    );

    return resultat.rows;
}

async function trouverUtilisateurParNumero(numero) {
    const numeroNormalise = normaliserNumero(numero);
    const db = postgresConfigure();

    const resultat = await db.query(
        `SELECT ${COLONNES_UTILISATEUR}
         FROM utilisateurs
         WHERE numero = $1
         LIMIT 1`,
        [numeroNormalise]
    );

    return convertirUtilisateur(resultat.rows[0]);
}

async function trouverUtilisateurParIdentifiant(identifiant) {
    const db = postgresConfigure();

    const resultat = await db.query(
        `SELECT ${COLONNES_UTILISATEUR}
         FROM utilisateurs
         WHERE identifiant = $1
         LIMIT 1`,
        [String(identifiant || "").trim()]
    );

    return convertirUtilisateur(resultat.rows[0]);
}

module.exports = {
    creerUtilisateur,
    verifierConnexion,
    listerUtilisateursJJM,
    rechercherUtilisateursJJM,
    trouverUtilisateurParNumero,
    trouverUtilisateurParIdentifiant,
    creerCodeVerification,
    verifierCodeVerification,
    normaliserNumero,
    numeroValide
};
