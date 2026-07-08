import { app, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import { requireRole } from "../auth/authorize";

export async function adminReport(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {

    context.log(`Http function processed request for url "${request.url}"`);

    return { jsonBody: { report: "Only users with the Reports.Admin role can see this." } };
};

app.http('adminReport', {
    methods: ['GET'],
    authLevel: 'anonymous',
    handler: requireRole('Reports.Admin', adminReport)
});
