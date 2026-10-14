const { Pool } = require("pg");

let pool = null;

function postgresConfigure() {
    const connectionString =
        process.env.DATABASE_URL;

    if (!connectionString) {
        throw new Error(
            "DATABASE_URL n'est pas configurée."
        );
    }

    if (pool) {
        return pool;
    }

    pool = new Pool({
        connectionString,
        ssl: process.env.PGSSL === "true"
            ? { rejectUnauthorized: true }
            : undefined,
        connectionTimeoutMillis: 5000,
        idleTimeoutMillis: 30000,
        max: 5
    });

    pool.on("error", () => {
        console.error(
            "Erreur inattendue sur une connexion PostgreSQL inactive."
        );
    });

    return pool;
}

async function verifierConnexionPostgres() {
    const connexion = postgresConfigure();

    const resultat = await connexion.query(
        "SELECT 1 AS connexion_ok"
    );

    return resultat.rows[0].connexion_ok === 1;
}

async function fermerConnexionPostgres() {
    if (pool) {
        const anciennePool = pool;
        pool = null;
        await anciennePool.end();
    }
}

module.exports = {
    postgresConfigure,
    verifierConnexionPostgres,
    fermerConnexionPostgres
};
