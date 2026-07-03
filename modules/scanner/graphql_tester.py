"""
GraphQL Tester — detecta endpoints GraphQL e verifica introspection exposta,
queries sem autenticação e DoS por query aninhada.
"""
import requests, warnings, json
from core.utils import print_status

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

COMMON_ENDPOINTS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/query",
    "/gql", "/graph", "/graphiql", "/playground",
    "/api/v1/graphql", "/api/v2/graphql",
]

INTROSPECTION_QUERY = {"query": "{ __schema { types { name } } }"}

SQLI_QUERY = {"query": '{ user(id: "1 OR 1=1") { id name email } }'}

NESTED_QUERY = {"query": "{ user { posts { comments { author { posts { comments { id } } } } } } }"}

UNAUTH_QUERIES = [
    {"query": "{ users { id email password } }"},
    {"query": "{ admin { id token } }"},
    {"query": "{ me { id email role } }"},
]


class GraphQLTester:
    def __init__(self, target: str, context=None):
        self.target  = target
        self.context = context
        self.results = {
            "endpoints_found":   [],
            "introspection":     [],
            "unauth_data":       [],
            "injection_hints":   [],
            "dos_risk":          [],
        }

    def _post(self, url, query):
        try:
            r = requests.post(
                url, json=query, timeout=10, verify=False,
                headers={"Content-Type": "application/json",
                         "User-Agent": "Mozilla/5.0"}
            )
            return r
        except Exception:
            return None

    def discover_endpoints(self):
        print_status("GraphQL endpoint discovery...", "INFO")
        for path in COMMON_ENDPOINTS:
            url = self.target.rstrip("/") + path
            r = self._post(url, {"query": "{ __typename }"})
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if "data" in data or "errors" in data:
                        self.results["endpoints_found"].append(url)
                        if self.context:
                            self.context.add_url(url)
                        print_status(f"GraphQL encontrado: {url}", "SUCCESS")
                except Exception:
                    pass

    def test_introspection(self):
        for url in self.results["endpoints_found"]:
            r = self._post(url, INTROSPECTION_QUERY)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if data.get("data", {}).get("__schema"):
                        types = [t["name"] for t in data["data"]["__schema"]["types"] if not t["name"].startswith("__")]
                        finding = {
                            "url":      url,
                            "issue":    "GraphQL Introspection exposta",
                            "severity": "MEDIUM",
                            "types":    types[:20],
                            "source":   "GraphQLTester",
                        }
                        self.results["introspection"].append(finding)
                        if self.context:
                            self.context.add_finding(finding)
                        print_status(f"Introspection exposta em {url} — {len(types)} tipos.", "WARN")
                except Exception:
                    pass

    def test_unauth(self):
        for url in self.results["endpoints_found"]:
            for query in UNAUTH_QUERIES:
                r = self._post(url, query)
                if r and r.status_code == 200:
                    try:
                        data = r.json()
                        if data.get("data") and data["data"] != {"me": None}:
                            finding = {
                                "url":      url,
                                "issue":    "GraphQL query sem autenticação retornou dados",
                                "query":    query["query"],
                                "preview":  json.dumps(data.get("data",""))[:100],
                                "severity": "HIGH",
                                "source":   "GraphQLTester",
                            }
                            self.results["unauth_data"].append(finding)
                            if self.context:
                                self.context.add_finding(finding)
                            print_status(f"GraphQL dados não autenticados em {url}", "CRIT")
                    except Exception:
                        pass

    def test_dos_nested(self):
        for url in self.results["endpoints_found"]:
            r = self._post(url, NESTED_QUERY)
            if r:
                elapsed = r.elapsed.total_seconds() if hasattr(r, "elapsed") else 0
                if elapsed > 3 or r.status_code == 500:
                    finding = {
                        "url":      url,
                        "issue":    f"GraphQL vulnerável a query aninhada (DoS) — {elapsed:.1f}s",
                        "severity": "MEDIUM",
                        "source":   "GraphQLTester",
                    }
                    self.results["dos_risk"].append(finding)
                    if self.context:
                        self.context.add_finding(finding)
                    print_status(f"GraphQL DoS risk em {url} ({elapsed:.1f}s)", "WARN")

    def run(self):
        self.discover_endpoints()
        if self.results["endpoints_found"]:
            self.test_introspection()
            self.test_unauth()
            self.test_dos_nested()
        else:
            print_status("Nenhum endpoint GraphQL encontrado.", "INFO")
        return self.results
