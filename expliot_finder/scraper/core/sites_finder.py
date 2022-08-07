"""Search pages with CVE or ready exploits for captured 'service_version'.

Information detected by this module will be saved and returned in the following
form:

.. code-block:: python

    # Returns list of URLs that redirect to CVEs or exploits that match or
    # partially match to captured service version.
    [
        'https://www.exploit-db.com/exploits/21314',
        'https://www.cvedetails.com/vulnerability-list/vendor_id-120/product_id-317/SSH-Ssh2.html',
        ...
    ]
"""

__all__ = ("GoogleSitesFinder",)

from urllib import parse

from requests_html import AsyncHTMLSession, HTMLResponse


class GoogleSitesFinder:
    """Finder of ready exploits and CVEs in web for captured 'service'.

    Using a Google search engine, the methods will make queries to find sites
    with matching exploits and the CVE for the version of the service that was
    captured after the target was scanned and currently is iterated in
    '__main__.py'. If multiple versions of services have been captured then a
    class('GoogleSitesFinder') instance will be created several times and each
    time with a next one successively captured version of the service. Found
    pages will be filtered according to the domain of the page (selected
    domains contain appropriate content). Sample return by this module:

    Attributes:
        service_version:
            Version of the service that was captured after the target was
            scanned by 'vulnerability_scanner' module.
        search_query:
            String contains ('base_query' + service_version) and by
            combining those two string we get query that's can be used to
            search ready exploits and CVEs in google.

    .. automethod:: __send_search_query
    .. automethod:: __extract_urls
    """

    __slots__ = ("_search_query",)

    def __init__(self, service_version: str) -> None:
        """Init GoogleSitesFinder class.

        Args:
            service_version:
                Captured service version that will be used as a search query for
                finding a ready exploits and CVE in web.
        """
        self.search_query: str = service_version

    def __repr__(self) -> str:
        """Print class name and class attributes.

        Returns:
            'GoogleSitesFinder' as the class name and attributes of this class.
        """
        return f"{self.__class__.__name__}({vars(self)!r})"

    @property
    def search_query(self) -> str:
        """Get google_query.

        Returns:
            'search_query' that will be used in google search engine to find
             ready exploits or CVE.
        """
        return self._search_query + " exploit"

    @search_query.setter
    def search_query(self, service_version: str) -> None:
        """Set 'search_query' value by combining base query and services version.

        Base query value: 'https://www.google.co.uk/search?q='

        Args:
            service_version:
                Version of the service that was captured after the target
                was scanned by 'vulnerability_scanner' module.
        """
        base_query: str = "https://www.google.co.uk/search?q="
        self._search_query = base_query + parse.quote_plus(service_version)

    @staticmethod
    async def __send_search_query(search_query: str) -> HTMLResponse:
        """Send a 'search_query' to async consumable session by using GET request.

        Args:
            search_query:
                Search query used to find ready exploits or CVE's for
                captured 'service_version'.

        Returns:
            HTML response object. The content of the answer is exactly like
            that itself as if the query was made by google search engine.
        """
        return await AsyncHTMLSession().get(search_query)

    @staticmethod
    def __extract_urls(response: HTMLResponse) -> list[str]:
        """Extract all URLs from HTML response.

        HTML response will store URLs to different sites and other content.
        This method will extract only URLs to site from whole HTMLResponse
        content.

        Args:
            response:
                HTML response, store content returned after executing a
                query to Google search engine.

        Returns:
            Links to different pages extracted from HTML response content.
        """
        return list(response.html.absolute_links)

    @staticmethod
    def filter_extracted_urls(site: str, urls: list[str]) -> list[str]:
        """Filter extracted URLs to find pages with CVE or ready exploits.

        Args:
            site:
                The value depends on provided parameter in
                'exploit_finder.executor' but can be one of:
                    - 'https://www.exploit-db.com'
                    - 'https://www.cvedetails.com'
                Only pages with those domains will be returned.
            urls:
                Links to different pages extracted from HTML response content.

        Returns:
            URLs that redirect to CVEs or exploits that match or partially
            match to captured service version.
        """
        return [url for url in urls if url.startswith(site)]

    async def search_for_pages(self, site: str) -> list[str]:
        """Run a functions to find pages with ready exploits or CVEs.

        Ready exploits and CVEs will be searched for captured version of the
        service that was captured after the target was scanned by
        'vulnerability_scanner' module.

        Args:
            site:
                What site should the scraper look for. Can be one of:
                    - 'https://www.exploit-db.com'
                    - 'https://www.cvedetails.com'

        Returns:
            List of pages containing ready-made exploits for detected
            'service_version' or pages that contain information about detected
            'service_version'.
        """
        response: HTMLResponse = await self.__send_search_query(self.search_query)
        return self.filter_extracted_urls(site, urls=self.__extract_urls(response))
