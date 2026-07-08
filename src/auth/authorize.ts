import { HttpHandler, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";

/**
 * Shape of the identity that Easy Auth (App Service Authentication) forwards
 * to the function in the `x-ms-client-principal` header (base64-encoded JSON).
 */
export interface ClientPrincipal {
    auth_typ: string;
    name_typ: string;
    role_typ: string;
    claims: { typ: string; val: string }[];
}

export function getClientPrincipal(request: HttpRequest): ClientPrincipal | null {
    const header = request.headers.get("x-ms-client-principal");
    if (!header) return null;
    try {
        return JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    } catch {
        return null;
    }
}

/** All values of a claim type, e.g. getClaims(req, "roles") or getClaims(req, "groups"). */
export function getClaims(request: HttpRequest, type: string): string[] {
    const principal = getClientPrincipal(request);
    if (!principal) return [];
    return principal.claims.filter((c) => c.typ === type).map((c) => c.val);
}

// Easy Auth does not run locally under `func start`. Set DISABLE_AUTH_FOR_LOCAL_DEV
// in local.settings.json to skip the checks on your machine. Never set it in Azure.
function authDisabledForLocalDev(): boolean {
    return process.env.DISABLE_AUTH_FOR_LOCAL_DEV === "true";
}

function unauthorized(): HttpResponseInit {
    return { status: 401, jsonBody: { error: "Unauthenticated" } };
}

function forbidden(message: string): HttpResponseInit {
    return { status: 403, jsonBody: { error: message } };
}

/** Allows only callers whose token carries the given app role (`roles` claim). */
export function requireRole(role: string, handler: HttpHandler): HttpHandler {
    return async (request: HttpRequest, context: InvocationContext) => {
        if (authDisabledForLocalDev()) return handler(request, context);
        if (!getClientPrincipal(request)) return unauthorized();
        if (!getClaims(request, "roles").includes(role)) {
            return forbidden(`Missing required role: ${role}`);
        }
        return handler(request, context);
    };
}

/** Allows only members of the given Entra security group (`groups` claim, by object ID). */
export function requireGroup(groupId: string, handler: HttpHandler): HttpHandler {
    return async (request: HttpRequest, context: InvocationContext) => {
        if (authDisabledForLocalDev()) return handler(request, context);
        if (!getClientPrincipal(request)) return unauthorized();
        if (!getClaims(request, "groups").includes(groupId)) {
            return forbidden("Not a member of the required group");
        }
        return handler(request, context);
    };
}
