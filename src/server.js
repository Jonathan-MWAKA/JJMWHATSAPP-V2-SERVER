require("dotenv").config();

const express = require("express");
const { rateLimit } = require("express-rate-limit");
const cors = require("cors");
const http = require("http");
const WebSocket = require("ws");
const jwt = require("jsonwebtoken");

const {
    creerUtilisateur,
    verifierConnexion,
    trouverUtilisateurParNumero,
    trouverUtilisateurParIdentifiant,
    creerCodeVerification,
    verifierCodeVerification,
    numeroValide
} = require("./users");

const {
    ajouterMessage,
    chargerMessages,
    messagesPourUtilisateur,
    marquerCommeLivre
} = require("./messages");

const app = express();
const serveur = http.createServer(app);

const PORT = process.env.PORT || 8080;

const connexionsJJM = new Map();

function utilisateurConnecteJJM(identifiant) {

    const socket =
        connexionsJJM.get(
            identifiant
        );

    return (
        socket != null
        && socket.readyState
            === WebSocket.OPEN
    );
}

function nombreUtilisateursConnectesJJM() {

    let nombre = 0;

    for (
        const socket
        of connexionsJJM.values()
    ) {

        if (
            socket.readyState
                === WebSocket.OPEN
        ) {
            nombre++;
        }
    }

    return nombre;
}


function diffuserPresenceJJM(
    type,
    identifiant
) {

    const message =
        JSON.stringify({
            type: type,
            identifiant: identifiant
        });

    for (
        const socket
        of connexionsJJM.values()
    ) {

        if (
            socket.readyState
                === WebSocket.OPEN
        ) {

            socket.send(message);
        }
    }
}

const originesAutoriseesJJM = (
    process.env.JJM_CORS_ORIGINS || ""
)
    .split(",")
    .map((origine) => origine.trim())
    .filter(Boolean);

app.use(cors({
    origin: (origine, callback) => {
        // Les applications natives peuvent ne pas envoyer d'en-tête Origin.
        if (!origine) {
            return callback(null, true);
        }

        // Les navigateurs ne sont autorisés que pour les origines configurées.
        if (originesAutoriseesJJM.includes(origine)) {
            return callback(null, true);
        }

        // Refuser les autres origines web.
        return callback(null, false);
    }
}));
app.use(express.json({ limit: "32kb" }));

const reponseLimite = {
    ok: false,
    message: "Trop de tentatives. Réessayez plus tard."
};

const limiteDemandeCode = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: reponseLimite
});

const limiteVerificationCode = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: reponseLimite
});

const limiteConnexion = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: reponseLimite
});

const limiteInscription = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: reponseLimite
});

app.post(
    "/api/demander-code",
    limiteDemandeCode,
    async (req, res) => {

        try {

            const numero =
                String(
                    req.body.numero || ""
                ).trim();

            if (!numero) {
                return res.status(400).json({
                    ok: false,
                    message:
                        "Numéro obligatoire."
                });
            }

            const utilisateur =
                trouverUtilisateurParNumero(
                    numero
                );

            if (!utilisateur) {
                return res.status(404).json({
                    ok: false,
                    message:
                        "Numéro non enregistré dans JJM."
                });
            }

            const code =
                creerCodeVerification(
                    numero
                );

            // Le code de vérification ne doit jamais apparaître dans les journaux.
            // L'envoi réel du code nécessitera un fournisseur SMS.

            res.json({
                ok: true,
                message:
                    "Code de vérification généré."
            });

        } catch (e) {

            console.error(
                "Erreur demande code JJM :",
                e
            );

            res.status(500).json({
                ok: false,
                message:
                    "Erreur interne du serveur."
            });
        }
    }
);

app.post("/api/verifier-code", limiteVerificationCode, (req, res) => {

    try {

        const numero =
            String(
                req.body.numero || ""
            ).trim();

        const code =
            String(
                req.body.code || ""
            ).trim();

        if (!numero || !code) {
            return res.status(400).json({
                ok: false,
                message:
                    "Numéro et code obligatoires."
            });
        }

        const utilisateur =
            trouverUtilisateurParNumero(
                numero
            );

        if (!utilisateur) {
            return res.status(404).json({
                ok: false,
                message:
                    "Ce numéro n'est pas enregistré sur JJM."
            });
        }

        const valide =
            verifierCodeVerification(
                numero,
                code
            );

        if (!valide) {
            return res.status(401).json({
                ok: false,
                message:
                    "Code incorrect ou expiré."
            });
        }

        const secret =
            process.env.JJM_JWT_SECRET;

        if (!secret) {
            return res.status(500).json({
                ok: false,
                message:
                    "JJM_JWT_SECRET n'est pas configuré."
            });
        }

        const token =
            jwt.sign(
                {
                    sub: utilisateur.id,
                    identifiant:
                        utilisateur.identifiant
                },
                secret,
                {
                    expiresIn: "30d"
                }
            );

        res.json({
            ok: true,
            token,
            utilisateur: {
                id: utilisateur.id,
                identifiant:
                    utilisateur.identifiant,
                nom:
                    utilisateur.nom,
                numero:
                    utilisateur.numero
            }
        });

    } catch (e) {

        console.error(
            "Erreur vérification code JJM :",
            e
        );

        res.status(500).json({
            ok: false,
            message:
                "Erreur interne du serveur."
        });
    }
});

app.post("/api/register", limiteInscription, async (req, res) => {

    try {

        const nom =
            String(req.body.nom || "").trim();

        const numero =
            String(req.body.numero || "").trim();

        const motDePasse =
            String(req.body.motDePasse || "");

        if (
            !nom ||
            !numero ||
            !motDePasse
        ) {
            return res.status(400).json({
                ok: false,
                message:
                    "Nom, numéro et mot de passe obligatoires."
            });
        }

        if (nom.length > 80) {
            return res.status(400).json({
                ok: false,
                message: "Le nom ne peut pas dépasser 80 caractères."
            });
        }

        if (!numeroValide(numero)) {
            return res.status(400).json({
                ok: false,
                message: "Le numéro congolais est invalide."
            });
        }

        if (motDePasse.length < 6 || motDePasse.length > 128) {
            return res.status(400).json({
                ok: false,
                message: "Le mot de passe doit contenir entre 6 et 128 caractères."
            });
        }

        const utilisateur =
            await creerUtilisateur(
                nom,
                numero,
                motDePasse
            );

        res.status(201).json({
            ok: true,
            utilisateur: {
                id: utilisateur.id,
                identifiant:
                    utilisateur.identifiant,
                nom: utilisateur.nom,
                numero: utilisateur.numero
            }
        });

    } catch (e) {

        res.status(409).json({
            ok: false,
            message: e.message
        });
    }
});

app.post("/api/login", limiteConnexion, async (req, res) => {

    try {

        const numero =
            String(req.body.numero || "").trim();

        const motDePasse =
            String(req.body.motDePasse || "");

        const utilisateur =
            await verifierConnexion(
                numero,
                motDePasse
            );

        if (!utilisateur) {
            return res.status(401).json({
                ok: false,
                message:
                    "Numéro ou mot de passe incorrect."
            });
        }

        const secret =
            process.env.JJM_JWT_SECRET;

        if (!secret) {
            return res.status(500).json({
                ok: false,
                message:
                    "JJM_JWT_SECRET n'est pas configuré."
            });
        }

        const token =
            jwt.sign(
                {
                    sub: utilisateur.id,
                    identifiant:
                        utilisateur.identifiant
                },
                secret,
                {
                    expiresIn: "30d"
                }
            );

        res.json({
            ok: true,
            token,
            utilisateur: {
                id: utilisateur.id,
                identifiant:
                    utilisateur.identifiant,
                nom: utilisateur.nom,
                numero: utilisateur.numero
            }
        });

    } catch (e) {

        res.status(500).json({
            ok: false,
            message:
                "Erreur interne du serveur."
        });
    }
});

function authentifierJJM(req, res, next) {

    const autorisation =
        req.headers.authorization || "";

    if (!autorisation.startsWith("Bearer ")) {
        return res.status(401).json({
            ok: false,
            message: "Token d'authentification manquant."
        });
    }

    const token =
        autorisation.substring(7).trim();

    const secret =
        process.env.JJM_JWT_SECRET;

    if (!secret) {
        return res.status(500).json({
            ok: false,
            message: "JJM_JWT_SECRET n'est pas configuré."
        });
    }

    try {

        const contenu =
            jwt.verify(
                token,
                secret
            );

        req.utilisateurJJM = contenu;

        next();

    } catch (e) {

        return res.status(401).json({
            ok: false,
            message: "Token invalide ou expiré."
        });
    }
}

app.get("/api/me", authentifierJJM, (req, res) => {

    const utilisateur =
        trouverUtilisateurParIdentifiant(
            req.utilisateurJJM.identifiant
        );

    if (!utilisateur) {
        return res.status(404).json({
            ok: false,
            message:
                "Utilisateur introuvable."
        });
    }

    res.json({
        ok: true,
        utilisateur: {
            id: utilisateur.id,
            identifiant:
                utilisateur.identifiant,
            nom: utilisateur.nom,
            numero: utilisateur.numero
        }
    });
});

app.get(
    "/api/utilisateurs-inscrits",
    authentifierJJM,
    (req, res) => {
        const users = require("./users");

        const utilisateurs = users.listerUtilisateursJJM(
            req.utilisateurJJM.identifiant
        ).map(utilisateur => {
            const socket = connexionsJJM.get(
                utilisateur.identifiant
            );

            return {
                ...utilisateur,
                enLigne: !!(
                    socket &&
                    socket.readyState === WebSocket.OPEN
                )
            };
        });

        res.json({
            ok: true,
            utilisateurs
        });
    }
);

app.get(
    "/api/rechercher-utilisateurs",
    authentifierJJM,
    (req, res) => {
        const terme = String(req.query.q || "").trim();

        if (terme.length < 2) {
            return res.json({
                ok: true,
                utilisateurs: []
            });
        }

        const users = require("./users");
        const resultats = users.rechercherUtilisateursJJM(
            terme,
            req.utilisateurJJM.identifiant
        );

        res.json({
            ok: true,
            utilisateurs: resultats.map(utilisateur => ({
                identifiant: utilisateur.identifiant,
                nom: utilisateur.nom,
                numero: utilisateur.numero
            }))
        });
    }
);

app.get(
    "/api/utilisateur-par-numero",
    authentifierJJM,
    (req, res) => {

        const numero =
            String(
                req.query.numero || ""
            ).trim();

        if (!numero) {
            return res.status(400).json({
                ok: false,
                message:
                    "Numéro obligatoire."
            });
        }

        const utilisateur =
            require("./users")
                .trouverUtilisateurParNumero(
                    numero
                );

        if (!utilisateur) {
            return res.status(404).json({
                ok: false,
                message:
                    "Utilisateur JJM introuvable."
            });
        }

        res.json({
            ok: true,
            utilisateur: {
                identifiant:
                    utilisateur.identifiant,
                nom:
                    utilisateur.nom,
                numero:
                    utilisateur.numero
            }
        });
    }
);

app.post(
    "/api/utilisateurs-par-numeros",
    authentifierJJM,
    (req, res) => {

        const numeros =
            Array.isArray(req.body.numeros)
                ? req.body.numeros
                : [];

        if (numeros.length > 100) {
            return res.status(400).json({
                ok: false,
                message: "Maximum 100 numéros par requête."
            });
        }

        if (numeros.length === 0) {
            return res.json({
                ok: true,
                utilisateurs: []
            });
        }

        const users =
            require("./users");

        const utilisateurs = [];

        for (const numero of numeros) {

            const utilisateur =
                users.trouverUtilisateurParNumero(
                    numero
                );

            if (utilisateur) {
                utilisateurs.push({
                    identifiant:
                        utilisateur.identifiant,
                    nom:
                        utilisateur.nom,
                    numero:
                        utilisateur.numero
                });
            }
        }

        res.json({
            ok: true,
            utilisateurs
        });
    }
);

app.post(
    "/api/statuts-utilisateurs",
    authentifierJJM,
    (req, res) => {

        const identifiants =
            Array.isArray(req.body.identifiants)
                ? req.body.identifiants
                : [];

        if (identifiants.length > 100) {
            return res.status(400).json({
                ok: false,
                message: "Maximum 100 identifiants par requête."
            });
        }

        const statuts = {};

        for (const identifiant of identifiants) {

            const id =
                String(identifiant || "").trim();

            if (!id) {
                continue;
            }

            statuts[id] =
                utilisateurConnecteJJM(id);
        }

        res.json({
            ok: true,
            statuts
        });
    }
);

app.post(
    "/api/historique-conversation",
    authentifierJJM,
    (req, res) => {

        const autreUtilisateur =
            String(
                req.body.autreUtilisateur || ""
            ).trim();

        if (!autreUtilisateur) {
            return res.status(400).json({
                ok: false,
                erreur: "Utilisateur destinataire manquant"
            });
        }

        const messages =
            chargerMessages();

        const identifiantConnecte = req.utilisateurJJM.identifiant;

        const historique =
            messages.filter(
                message =>
                    (
                        message.expediteur ===
                            identifiantConnecte
                        &&
                        message.destinataire ===
                            autreUtilisateur
                    )
                    ||
                    (
                        message.expediteur ===
                            autreUtilisateur
                        &&
                        message.destinataire ===
                            identifiantConnecte
                    )
            );

        res.json({
            ok: true,
            messages: historique
        });
    }
);

app.get(
    "/api/messages-hors-ligne",
    authentifierJJM,
    (req, res) => {

        const messages =
            messagesPourUtilisateur(
                req.utilisateurJJM.identifiant
            );

        res.json({
            ok: true,
            nombre: messages.length,
            messages
        });
    }
);

app.get("/health", (req, res) => {
    res.json({
        ok: true,
        service: "JJMWHATSAPP_V2",
        message: "Serveur JJMWHATSAPP V2 opérationnel",
        websocket: {
            actif: true,
            utilisateursConnectes:
                nombreUtilisateursConnectesJJM()
        }
    });
});

const wss = new WebSocket.Server({
    server: serveur,
    maxPayload: 16 * 1024
});

wss.on("connection", (socket, req) => {

    const autorisation =
        String(req.headers.authorization || "");

    const correspondance =
        autorisation.match(/^Bearer\s+([^\s]+)$/i);

    const token =
        correspondance ? correspondance[1] : null;

    const secret =
        process.env.JJM_JWT_SECRET;

    if (!token || !secret) {

        socket.close(
            1008,
            "Authentification requise"
        );

        return;
    }

    try {

        const contenu =
            jwt.verify(
                token,
                secret
            );

        socket.utilisateurJJM = contenu;

        connexionsJJM.set(
            contenu.identifiant,
            socket
        );

        console.log(
            "WebSocket authentifié :",
            contenu.identifiant
        );

        console.log(
            "Utilisateurs WebSocket connectés :",
            nombreUtilisateursConnectesJJM()
        );

        diffuserPresenceJJM(
            "utilisateur_en_ligne",
            contenu.identifiant
        );

        socket.send(
            JSON.stringify({
                type: "connexion",
                ok: true,
                message:
                    "Connexion WebSocket JJM réussie",
                identifiant:
                    contenu.identifiant
            })
        );

        const messagesEnAttente =
            messagesPourUtilisateur(
                contenu.identifiant
            );

        for (
            const messageEnAttente
            of messagesEnAttente
        ) {

            socket.send(
                JSON.stringify(
                    messageEnAttente
                )
            );
        }

        if (
            messagesEnAttente.length > 0
        ) {

            const nombreLivres =
                marquerCommeLivre(
                    contenu.identifiant
                );

            console.log(
                "Messages hors ligne synchronisés :",
                contenu.identifiant,
                nombreLivres
            );
        }

    } catch (e) {

        socket.close(
            1008,
            "Token invalide ou expiré"
        );

        return;
    }

    socket.on("message", (donnees) => {

        try {

            const message =
                JSON.parse(
                    donnees.toString()
                );

            if (
                message.type !==
                "message"
            ) {
                socket.send(
                    JSON.stringify({
                        type: "erreur",
                        ok: false,
                        message:
                            "Type de message inconnu."
                    })
                );

                return;
            }

            const destinataire =
                String(
                    message.destinataire || ""
                ).trim();

            const texteMessage =
                String(
                    message.texte || ""
                ).trim();

            if (
                !destinataire ||
                !texteMessage
            ) {
                socket.send(
                    JSON.stringify({
                        type: "erreur",
                        ok: false,
                        message:
                            "Destinataire et texte obligatoires."
                    })
                );

                return;
            }

            if (texteMessage.length > 4000) {
                socket.send(
                    JSON.stringify({
                        type: "erreur",
                        ok: false,
                        message: "Le message dépasse 4 000 caractères."
                    })
                );
                return;
            }

            if (!trouverUtilisateurParIdentifiant(destinataire)) {
                socket.send(
                    JSON.stringify({
                        type: "erreur",
                        ok: false,
                        message: "Destinataire JJM introuvable."
                    })
                );
                return;
            }

            const messageJJM = {

                type:
                    "nouveau_message",

                id:
                    require("crypto")
                        .randomUUID(),

                expediteur:
                    socket.utilisateurJJM
                        .identifiant,

                destinataire,

                texte:
                    texteMessage,

                date:
                    new Date().toISOString()
            };

            const connexionDestinataire =
                connexionsJJM.get(
                    destinataire
                );

            const destinataireEnLigne =
                utilisateurConnecteJJM(
                    destinataire
                );

            // Tous les messages sont sauvegardés,
            // qu'ils soient envoyés en ligne ou conservés hors ligne.

            messageJJM.livre =
                destinataireEnLigne;

            ajouterMessage(
                messageJJM
            );

            if (
                destinataireEnLigne
            ) {

                connexionDestinataire.send(
                    JSON.stringify(
                        messageJJM
                    )
                );

                console.log(
                    "Message envoyé et sauvegardé :",
                    destinataire
                );

            } else {

                console.log(
                    "Message conservé hors ligne pour :",
                    destinataire
                );
            }

            socket.send(
                JSON.stringify({
                    type:
                        "message_envoye",

                    ok: true,

                    enLigne:
                        destinataireEnLigne,

                    message:
                        messageJJM
                })
            );

            console.log(
                "Message :",
                socket.utilisateurJJM
                    .identifiant,
                "->",
                destinataire
            );

        } catch (e) {
            console.error("Erreur traitement message WebSocket JJM :", e);


            socket.send(
                JSON.stringify({
                    type: "erreur",
                    ok: false,
                    message:
                        "Message invalide."
                })
            );
        }
    });

    socket.on("close", () => {

        const utilisateur = socket.utilisateurJJM;

        // Une connexion refusée peut se fermer sans utilisateur authentifié.
        if (!utilisateur || !utilisateur.identifiant) {
            return;
        }

        const identifiant = utilisateur.identifiant;

        if (
            connexionsJJM.get(identifiant)
            === socket
        ) {
            connexionsJJM.delete(identifiant);

            diffuserPresenceJJM(
                "utilisateur_hors_ligne",
                identifiant
            );
        }

        console.log(
            "WebSocket déconnecté :",
            identifiant
        );

        console.log(
            "Utilisateurs WebSocket connectés :",
            nombreUtilisateursConnectesJJM()
        );
    });
});

serveur.listen(PORT, "0.0.0.0", () => {

    console.log(
        `Serveur JJMWHATSAPP V2 démarré sur le port ${PORT}`
    );

    console.log(
        `http://127.0.0.1:${PORT}/health`
    );
});
