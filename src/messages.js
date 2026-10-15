const { postgresConfigure } = require("./database");

function convertirMessage(ligne) {
    return {
        id: ligne.id,
        expediteur: ligne.expediteur,
        destinataire: ligne.destinataire,
        texte: ligne.texte,
        date: ligne.date instanceof Date
            ? ligne.date.toISOString()
            : ligne.date,
        livre: ligne.livre
    };
}

async function chargerMessages() {
    const db = postgresConfigure();

    const resultat = await db.query(
        `SELECT
            id,
            expediteur,
            destinataire,
            texte,
            date_message AS date,
            livre
         FROM messages
         ORDER BY date_message ASC`
    );

    return resultat.rows.map(convertirMessage);
}

async function ajouterMessage(message) {
    const db = postgresConfigure();

    await db.query(
        `INSERT INTO messages
            (id, expediteur, destinataire, texte, date_message, livre)
         VALUES
            ($1, $2, $3, $4, COALESCE($5::timestamptz, NOW()), $6)`,
        [
            message.id,
            message.expediteur,
            message.destinataire,
            message.texte,
            message.date || null,
            message.livre === true
        ]
    );

    return message;
}

async function messagesPourUtilisateur(identifiant) {
    const db = postgresConfigure();

    const resultat = await db.query(
        `SELECT
            id,
            expediteur,
            destinataire,
            texte,
            date_message AS date,
            livre
         FROM messages
         WHERE destinataire = $1
           AND livre = FALSE
         ORDER BY date_message ASC`,
        [identifiant]
    );

    return resultat.rows.map(message => ({
        type: "nouveau_message",
        ...convertirMessage(message)
    }));
}

async function marquerCommeLivre(identifiant) {
    const db = postgresConfigure();

    const resultat = await db.query(
        `UPDATE messages
         SET livre = TRUE
         WHERE destinataire = $1
           AND livre = FALSE`,
        [identifiant]
    );

    return resultat.rowCount;
}

module.exports = {
    chargerMessages,
    ajouterMessage,
    messagesPourUtilisateur,
    marquerCommeLivre
};
