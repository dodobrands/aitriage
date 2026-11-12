export async function getServiceReport(accessToken: string, reportId: string) {
  // ruleid: ENTR-SENSITIVE-LOG
  console.log("getServiceReport", accessToken, reportId);
  return api.get(reportId);
}
