const log4js = require("log4js");
const iniParser = require("multi-ini");
const fs = require("fs");

let configuration;
// Log4js configuration
log4js.configure({
    appenders: {
        'console': { type: 'stdout' },
        default: { type: 'file', filename: 'BotsListServer.log', maxLogSize: 1048576, backups: 3, compress: true }
    },
    categories: {
        default: { appenders: ['default', 'console'], level: 'debug' }
    }
});

let loggerInstance = log4js.getLogger('BotsListServer');

if (fs.existsSync("config.ini")) {
    configuration = iniParser.read("./config.ini");
} else {
    loggerInstance.error("NodeListServer failed to start due to a missing 'config.ini' file.");
    loggerInstance.error("Exiting...");
    process.exit(1);
}

function translateConfigOptionToBool(value) {
    if(value === "true" || value === 1) {
        return true;
    } else {
        return false;
    }
}
const expressServer = require("express");
const expressRateLimiter = require("express-rate-limit");
const expressApp = expressServer();
const bodyParser = require("body-parser");
const limiter = expressRateLimiter({
    windowMs: configuration.Security.rateLimiterWindowMs,
    max: configuration.Security.rateLimiterMaxApiRequestsPerWindow
});

expressApp.use(limiter);
expressApp.use(bodyParser.json());
expressApp.use(bodyParser.urlencoded({ extended: true }));

var knownServers = [];
var allowedServerAddresses = [];
if(translateConfigOptionToBool(configuration.Auth.useAccessControl)) {
    allowedServerAddresses = configuration.Auth.allowedIpAddresses.split(",");
}

function apiCheckKey(clientKey) {
    if(clientKey === configuration.Auth.communicationKey) {
        return true;
    } else {
        return false;
    }
}

function apiIsKeyFromRequestIsBad(req) {
    if(typeof req.body.serverKey === "undefined" || !apiCheckKey(req.body.serverKey))
    {
        loggerInstance.warn(`${req.ip} used a wrong key: ${req.body.serverKey}`);
        return true;
    } else {
        return false;
    }
}

function apiDoesServerExist(uuid) {
    var doesExist = knownServers.filter((server) => server.uuid === uuid);
    if(doesExist.length > 0) {
        return true;
    }
    return false;
}

function apiDoesThisServerExistByAddressPort(ipAddress, port) {
    var doesExist = knownServers.filter((servers) => (servers.ip === ipAddress && servers.port === port));
    if(doesExist.length > 0) {
        return true;
    }
    return false;
}

function denyRequest (req, res) {
    loggerInstance.warn(`Request from ${req.ip} denied. Tried ${req.method} method on path: ${req.path}`);
    return res.sendStatus(400);
}

function apiGetServerList(req, res) {
    loggerInstance.info(`Get server list from: ${req.serverKey}`);
    if(apiIsKeyFromRequestIsBad(req))
    {
        return res.sendStatus(400);
    }
    else
    {
        loggerInstance.info(`${req.ip} accepted; communication key matched: '${req.body.serverKey}'`);
    }
    var serverList = [];
    knownServers = knownServers.filter((freshServer) => (freshServer.lastUpdated >= Date.now()));
    knownServers.forEach((knownServer) => {
        if(translateConfigOptionToBool(configuration.Pruning.dontShowServersOnSameIp)) {
            if(knownServer.ip === req.ip) {
                loggerInstance.info(`Skipped server '${knownServer.uuid}', reason: it's hosted on the same IP as this client`);
                return;
            }
        }

        serverList.push({
            "IP": knownServer.ip,
            "Name": knownServer.name,
            "Port": parseInt(knownServer.port, 10),
            "Players": parseInt(knownServer.players, 10),
            "Capacity": parseInt(knownServer.capacity, 10),
            "Extras": knownServer.extras
        });
    });

    // loggerInstance.info(`Current server list ${serverList.length}`);
    var returnedServerList = {
        "Count": serverList.length,
        "Servers": serverList,
        "updateFrequency": configuration.Pruning.ingameUpdateFrequency
    };
    loggerInstance.info(`Replying to ${req.ip} with known server list.`);
    return res.json(returnedServerList);
}

function apiAddToServerList(req, res) {
    if(apiIsKeyFromRequestIsBad(req))
    {
        return res.sendStatus(400);
    }

    if(translateConfigOptionToBool(configuration.Auth.useAccessControl) && !allowedServerAddresses.includes(req.ip)) {
        loggerInstance.warn(`Request from ${req.ip} denied: Not in ACL.`);
        return res.sendStatus(403);
    }

    if(typeof req.body === "undefined") {
        loggerInstance.warn(`Request from ${req.ip} denied: There was no body attached to the request.`);
        return res.sendStatus(400);
    }

    if(typeof req.body.serverUuid === "undefined" || typeof req.body.serverName === "undefined" || typeof req.body.serverPort === "undefined") {
        loggerInstance.warn(`Request from ${req.ip} denied: UUID, name and/or port is bogus.`);
        return res.sendStatus(400);
    }

    if(isNaN(req.body.serverPort) || req.body.serverPort < 0 || req.body.serverPort > 65535) {
        loggerInstance.warn(`Request from ${req.ip} denied: Port was out of bounds.`);
        return res.sendStatus(400);
    }
    // 根据UUID确定server唯一性
    if(apiDoesServerExist(req.body.serverUuid)) {
        loggerInstance.warn(`Server UUID collision check failed for ${req.ip} with UUID '${req.body.serverUuid}'.`);
        return res.sendStatus(400);
    }
    if(apiDoesThisServerExistByAddressPort(req.ip, req.body.serverPort)) {
        // Collision - abort!
        loggerInstance.warn(`Server IP and Port collision check failed for ${req.ip} with UUID '${req.body.serverUuid}'.`);
        return res.sendStatus(400);
    }
    var newServer = {
        "uuid": req.body.serverUuid,
        "ip": req.ip,
        "name": req.body.serverName,
        "port": parseInt(req.body.serverPort, 10),
        "lastUpdated": (Date.now() + (configuration.Pruning.inactiveServerRemovalMinutes * 60 * 1000))
    };
    if(typeof req.body.serverPlayers === "undefined" || isNaN(req.body.serverPlayers)) {
        newServer["players"] = 0;
    } else {
        newServer["players"] = parseInt(req.body.serverPlayers, 10);
    }

    if(typeof req.body.serverCapacity === "undefined" || isNaN(req.body.serverCapacity)) {
        newServer["capacity"] = 0;
    } else {
        newServer["capacity"] = parseInt(req.body.serverCapacity, 10);
    }

    if(typeof req.body.serverExtras !== "undefined") {
        newServer["extras"] = req.body.serverExtras;
    } else {
        newServer["extras"] = "";
    }

    knownServers.push(newServer);
    loggerInstance.info(`New server added: '${req.body.serverName}' from ${req.ip}. UUID: '${req.body.serverUuid}'`);
    return res.send("OK\n");
}

function apiRemoveFromServerList(req, res) {
    if(apiIsKeyFromRequestIsBad(req))
    {
        return res.sendStatus(400);
    }
    if(translateConfigOptionToBool(configuration.Auth.useAccessControl) && !allowedServerAddresses.includes(req.ip)) {
        loggerInstance.warn(`Remove server request blocked from ${req.ip}.`);
        return res.sendStatus(403);
    }

    if(typeof req.body === "undefined") {
        loggerInstance.warn(`Request from ${req.ip} denied: no POST data was provided.`);
        return res.sendStatus(400);
    }

    if(typeof req.body.serverUuid === "undefined") {
        loggerInstance.warn(`Request from ${req.ip} denied: Server UUID was not provided.`);
        return res.sendStatus(400);
    }

    if(!apiDoesServerExist(req.body.serverUuid, knownServers)) {
        loggerInstance.warn(`Request from ${req.ip} denied: Can't delete server with UUID '${req.body.serverUuid}' from cache.`);
        return res.sendStatus(400);
    } else {
        knownServers = knownServers.filter((server) => server.uuid !== req.body.serverUuid);
        loggerInstance.info(`Deleted server '${req.body.serverUuid}' from cache (requested by ${req.ip}).`);
        return res.send("OK\n");
    }
}

function apiUpdateServerInList(req, res) {
    if(apiIsKeyFromRequestIsBad(req))
    {
        return res.sendStatus(400);
    }

    if(translateConfigOptionToBool(configuration.Auth.useAccessControl) && !allowedServerAddresses.includes(req.ip)) {
        loggerInstance.warn(`Update server request blocked from ${req.ip}.`);
        return res.sendStatus(403);
    }

    if(typeof req.body === "undefined") {
        loggerInstance.warn(`Request from ${req.ip} denied: There was no body attached to the request.`);
        return res.sendStatus(400);
    }

    if(typeof req.body.serverUuid === "undefined") {
        loggerInstance.warn(`Request from ${req.ip} denied: UUID was not provided.`);
        return res.sendStatus(400);
    }

    // Does the server even exist?
    if(!apiDoesServerExist(req.body.serverUuid)) {
        loggerInstance.warn(`Request from ${req.ip} denied: No such server with UUID '${req.body.serverUuid}'`);
        return res.sendStatus(400);
    }

    var serverInQuestion = knownServers.filter((server) => (server.uuid === req.body.serverUuid));
    var notTheServerInQuestion = knownServers.filter((server) => (server.uuid !== req.body.serverUuid));

    var updatedServer = [];
    updatedServer["uuid"] = serverInQuestion[0].uuid;
    updatedServer["ip"] = serverInQuestion[0].ip;

    updatedServer["port"] = serverInQuestion[0].port;
    updatedServer["capacity"] = serverInQuestion[0].capacity;

    if(typeof req.body.serverExtras !== "undefined") {
        updatedServer["extras"] = req.body.serverExtras.trim();
    } else {
        updatedServer["extras"] = serverInQuestion[0].extras;
    }

    if(typeof req.body.serverName !== "undefined") {
        updatedServer["name"] = req.body.serverName.trim();
    } else {
        updatedServer["name"] = serverInQuestion[0].name;
    }

    if(typeof req.body.serverPlayers !== "undefined") {
        if(isNaN(parseInt(req.body.serverPlayers, 10))) {
            updatedServer["players"] = 0;
        } else {
            updatedServer["players"] = parseInt(req.body.serverPlayers, 10);
        }
    } else {
        updatedServer["players"] = serverInQuestion[0].players;
    }

    if(typeof req.body.serverCapacity !== "undefined" || !isNaN(req.body.serverCapacity)) {
        updatedServer["capacity"] = parseInt(req.body.serverCapacity, 10);
    }

    updatedServer["lastUpdated"] = (Date.now() + (configuration.Pruning.inactiveServerRemovalMinutes * 60 * 1000));

    notTheServerInQuestion.push(updatedServer);
    knownServers = notTheServerInQuestion;

    loggerInstance.info(`Updated information for '${updatedServer.name}', requested by ${req.ip}`);
    return res.send("OK\n");
}

expressApp.get("/", denyRequest);
expressApp.post("/list", apiGetServerList);					// List of servers...
expressApp.post("/add", apiAddToServerList);				// Add a server to the list...
expressApp.post("/remove", apiRemoveFromServerList);		// Remove a server from the list...
expressApp.post("/update", apiUpdateServerInList);

expressApp.listen(configuration.Core.listenPort, () => console.log(`Listening on HTTP port ${configuration.Core.listenPort}!`));
