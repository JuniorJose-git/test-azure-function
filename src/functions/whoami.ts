import { app, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import { getClaims, getClientPrincipal } from "../auth/authorize";

export async function whoami(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {

    const principal = getClientPrincipal(request);
    if (!principal) {
        return { status: 401, jsonBody: { error: "No client principal. Is Easy Auth enabled on the Function App?" } };
    }

    return {
        jsonBody: {
            name: getClaims(request, principal.name_typ)[0] ?? getClaims(request, "preferred_username")[0],
            roles: getClaims(request, "roles"),
            groups: getClaims(request, "groups")
        }
    };
};

app.http('whoami', {
    methods: ['GET'],
    authLevel: 'anonymous',
    handler: whoami
});
