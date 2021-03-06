import responses

from compal import Compal


def load_login_responses(ip):
    # Response required by constructor
    responses.add(
        responses.Response(
            method="GET",
            url=f"http://{ip}/",
            status=302,
            headers={"Location": "../common_page/login.html"},
        )
    )
    responses.add(responses.GET, f"http://{ip}/common_page/login.html", body="dummy")

    # Successful login response
    responses.add(
        responses.POST, f"http://{ip}/xml/setter.xml", body="successful;SID=1025573888"
    )


@responses.activate
def test_successful_response():
    load_login_responses("router")
    router = Compal("router", "1234")
    router.login()
