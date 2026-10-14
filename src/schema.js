const { postgresConfigure } = require("./database");

async function initialiserSchema() {
    const db = postgresConfigure();

    await db.query(`
        CREATE TABLE IF NOT EXISTS utilisateurs (
            id UUID PRIMARY KEY,
            identifiant VARCHAR(32) NOT NULL UNIQUE,
            nom VARCHAR(80) NOT NULL,
            numero VARCHAR(20) NOT NULL UNIQUE,
            mot_de_passe_hash TEXT NOT NULL,
            cree_le TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id UUID PRIMARY KEY,
            expediteur VARCHAR(32) NOT NULL,
            destinataire VARCHAR(32) NOT NULL,
            texte TEXT NOT NULL,
            date_message TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            livre BOOLEAN NOT NULL DEFAULT FALSE
        )
    `);

    await db.query(`
        CREATE INDEX IF NOT EXISTS idx_messages_conversation
        ON messages (expediteur, destinataire, date_message)
    `);

    await db.query(`
        CREATE INDEX IF NOT EXISTS idx_messages_destinataire_non_livres
        ON messages (destinataire, date_message)
        WHERE livre = FALSE
    `);

    return true;
}

module.exports = { initialiserSchema };
