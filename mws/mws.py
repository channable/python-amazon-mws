#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Basic interface to Amazon MWS
# Based on http://code.google.com/p/amazon-mws-python
#

# Added for python 3.x implementation
from __future__ import absolute_import
import six

from urllib.parse import quote
import aiohttp
from aiohttp import HttpProcessingError
import hashlib
import hmac
import base64
import xmltodict
import re
try:
    from xml.etree.ElementTree import ParseError as XMLError
except ImportError:
    from xml.parsers.expat import ExpatError as XMLError
from time import strftime, gmtime

from requests.exceptions import HTTPError


__all__ = [
    'Feeds',
    'Inventory',
    'MWSError',
    'Reports',
    'Orders',
    'Products',
    'Recommendations',
    'Sellers',
]

# See https://images-na.ssl-images-amazon.com/images/G/01/mwsportal/doc/en_US/bde/MWSDeveloperGuide._V357736853_.pdf
# page 8 for a list of the end points and marketplace IDs

# PEP-8 corrections
MARKETPLACES = {
    "CA": "https://mws.amazonservices.ca",         # A2EUQ1WTGCTBG2
    "US": "https://mws.amazonservices.com",        # ATVPDKIKX0DER
    "DE": "https://mws-eu.amazonservices.com",     # A1PA6795UKMFR9
    "ES": "https://mws-eu.amazonservices.com",     # A1RKKUPIHCS9HS
    "FR": "https://mws-eu.amazonservices.com",     # A13V1IB3VIYZZH
    "IN": "https://mws.amazonservices.in",         # A21TJRUUN4KGV
    "IT": "https://mws-eu.amazonservices.com",     # APJ6JRA9NG5V4
    "UK": "https://mws-eu.amazonservices.com",     # A1F83G8C2ARO7P
    "JP": "https://mws.amazonservices.jp",         # A1VC38T7YXB528
    "CN": "https://mws.amazonservices.com.cn",     # AAHKV2X7AFYLW
    "MX": "https://mws.amazonservices.com.mx",     # A1AM78C64UM0Y8
}


class MWSError(Exception):
    """
        Main MWS Exception class
    """
    # Allows quick access to the response object.
    # Do not rely on this attribute, always check if its not None.
    response = None


def calc_md5(string):
    """Calculates the MD5 encryption for the given string
    :param string
    """
    md = hashlib.md5()
    md.update(string)
    # done for Python 3.x support. old version: return base64.encodestring(md.digest()).strip('\n')
    return base64.encodestring(md.digest()).strip(b'\n')


def remove_empty(d):
    """
        Helper function that removes all keys from a dictionary (d),
        that have an empty value.
        :param d
    """
    # done for Python 3.x support. old version: for key in d.keys()
    for key in list(d.keys()):
        if not d[key]:
            del d[key]
    return d


def remove_namespace(xml):
    regex = re.compile(' xmlns(:ns2)?="[^"]+"|(ns2:)|(xml:)')
    return regex.sub('', xml)


class DictWrapper(object):
    def __init__(self, xml, rootkey=None):
        self.original = xml
        self._rootkey = rootkey
        self._mydict = xmltodict.parse(remove_namespace(xml))
        # done for Python 3.x support. old version:
        # self._response_dict = self._mydict.get(self._mydict.keys()[0], self._mydict)
        self._response_dict = self._mydict.get(list(self._mydict.keys())[0], self._mydict)

    @property
    def parsed(self):
        if self._rootkey:
            return self._response_dict.get(self._rootkey)
        else:
            return self._response_dict


class DataWrapper(object):
    """
        Text wrapper in charge of validating the hash sent by Amazon.
    """
    def __init__(self, data, header):
        # done for Encoding-Decoding error . old version: self.original = data
        self.original = data.encode('utf-8')
        if 'content-md5' in header:
            hash_ = calc_md5(self.original).decode('utf-8')
            if header['content-md5'] != hash_:
                raise MWSError("Wrong Contentlength, maybe amazon error...")

    @property
    def parsed(self):
        return self.original


class MWS(object):
    """ Base Amazon API class """

    # This is used to post/get to the different uris used by amazon per api
    # ie. /Orders/2011-01-01
    # All subclasses must define their own URI only if needed
    URI = "/"

    # The API version varies in most amazon APIs
    VERSION = "2009-01-01"

    # There seem to be some xml namespace issues. therefore every api subclass
    # is recommended to define its namespace, so that it can be referenced
    # like so AmazonAPISubclass.NS.
    # For more information see http://stackoverflow.com/a/8719461/389453
    NS = ''

    # Some APIs are available only to either a "Merchant" or "Seller"
    # the type of account needs to be sent in every call to the amazon MWS.
    # This constant defines the exact name of the parameter Amazon expects
    # for the specific API being used.
    # All subclasses need to define this if they require another account type
    # like "Merchant" in which case you define it like so.
    # ACCOUNT_TYPE = "Merchant"
    # Which is the name of the parameter for that specific account type.
    ACCOUNT_TYPE = "SellerId"

    def __init__(self, access_key, secret_key, account_id, region='US', domain='', uri="", version="", auth_token=""):
        self.access_key = access_key
        self.secret_key = secret_key
        self.account_id = account_id
        self.auth_token = auth_token
        self.version = version or self.VERSION
        self.uri = uri or self.URI

        if domain:
            self.domain = domain
        elif region in MARKETPLACES:
            self.domain = MARKETPLACES[region]
        else:
            error_msg = "Incorrect region supplied ('%(region)s'). Must be one of the following: %(marketplaces)s" % {
                "marketplaces": ', '.join(list(MARKETPLACES.keys())),
                "region": region,
            }
            raise MWSError(error_msg)

    async def make_request(self, extra_data, method="GET", **kwargs):
        """Make request to Amazon MWS API with these parameters
            :param extra_data
            :param method
            :param kwargs
        """

        # Remove all keys with an empty value because
        # Amazon's MWS does not allow such a thing.
        extra_data = remove_empty(extra_data)

        params = {
            'AWSAccessKeyId': self.access_key,
            self.ACCOUNT_TYPE: self.account_id,
            'SignatureVersion': '2',
            'Timestamp': self.get_timestamp(),
            'Version': self.version,
            'SignatureMethod': 'HmacSHA256',
        }
        if self.auth_token:
            params['MWSAuthToken'] = self.auth_token
        params.update(extra_data)
        # used to it makes TypeError: quote_from_bytes() expected bytes.
        # old version: quote(params[k], safe='-_.~')
        request_description = '&'.join(['%s=%s' % (k, quote(str(params[k]), safe='-_.~')) for k in sorted(params)])
        signature = self.calc_signature(method, request_description)
        url = '%s%s?%s&Signature=%s' % (self.domain, self.uri, request_description, quote(signature))
        headers = {'User-Agent': 'python-amazon-mws/0.0.1 (Language=Python)'}
        headers.update(kwargs.get('extra_headers', {}))

        try:
            # Some might wonder as to why i don't pass the params dict as the params argument to request.
            # My answer is, here i have to get the url parsed string of params in order to sign it, so
            # if i pass the params dict as params to request, request will repeat that step because it will need
            # to convert the dict to a url parsed string, so why do it twice if i can just pass the full url :).
            response = await aiohttp.request(method, url, data=kwargs.get('body', ''), headers=headers)

            # When retrieving data from the response object,
            # be aware that response.content returns the content in bytes while response.text calls
            # response.content and converts it to unicode.
            data = await response.text()

            # Raise for status
            if 400 <= response.status:
                raise HttpProcessingError(code=response.status, message=data)

            # I do not check the headers to decide which content structure to server simply because sometimes
            # Amazon's MWS API returns XML error responses with "text/plain" as the Content-Type.
            try:
                # TODO DictWrapper can't parse the Amazon Browse Tree response.
                # TODO For that reason parsed_response returns None
                parsed_response = DictWrapper(data, extra_data.get("Action") + "Result")
            except XMLError:
                parsed_response = DataWrapper(data, response.headers)

        # done for Python 3.x support. Old version:     except HTTPError, e:
        except HttpProcessingError as e:
            error = MWSError(str(e))
            error.response = e.message
            raise error

        # Store the response object in the parsed_response for quick access
        parsed_response.response = response
        return parsed_response

    async def get_service_status(self):
        """
            Returns a GREEN, GREEN_I, YELLOW or RED status.
            Depending on the status/availability of the API its being called from.
        """

        return await self.make_request(extra_data=dict(Action='GetServiceStatus'))

    def calc_signature(self, method, request_description):
        """Calculate MWS signature to interface with Amazon
           :param method
           :param request_description
        """
        sig_data = six.b(method + '\n' + self.domain.replace('https://', '').lower() + '\n' + self.uri + '\n' + request_description)
        # done for Python 3.x support.
        key = six.b(self.secret_key)
        return base64.b64encode(hmac.new(key, sig_data, hashlib.sha256).digest())

    def get_timestamp(self):
        """
            Returns the current timestamp in proper format.
        """
        return strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())

    def enumerate_param(self, param, values):
        """
            Builds a dictionary of an enumerated parameter.
            Takes any iterable and returns a dictionary.

            :param param
            :param values

            ie.
            enumerate_param('MarketplaceIdList.Id', (123, 345, 4343))
            returns
            {
                MarketplaceIdList.Id.1: 123,
                MarketplaceIdList.Id.2: 345,
                MarketplaceIdList.Id.3: 4343
            }
        """
        params = {}
        if values is not None:
            if not param.endswith('.'):
                param = "%s." % param
            for num, value in enumerate(values):
                params['%s%d' % (param, (num + 1))] = value
        return params


class Feeds(MWS):
    """ Amazon MWS Feeds API """

    ACCOUNT_TYPE = "Merchant"

    async def submit_feed(self, feed, feed_type, marketplaceids=None,
                    content_type="text/xml", purge='false'):
        """
        Uploads a feed ( xml or .tsv ) to the seller's inventory.
        Can be used for creating/updating products on Amazon.
        :param feed
        :param feed_type
        :param marketplaceids
        :param content_type
        :param purge
        """
        data = dict(Action='SubmitFeed',
                    FeedType=feed_type,
                    PurgeAndReplace=purge)
        data.update(self.enumerate_param('MarketplaceIdList.Id.', marketplaceids))
        md = calc_md5(feed)
        return await self.make_request(data, method="POST", body=feed,
                                 extra_headers={'Content-MD5': md, 'Content-Type': content_type})

    async def get_feed_submission_list(self, feedids=None, max_count=None, feedtypes=None,
                                 processingstatuses=None, fromdate=None, todate=None):
        """
        Returns a list of all feed submissions submitted in the previous 90 days.
        That match the query parameters.
        :param feedids
        :param max_count
        :param feedtypes
        :param processingstatuses
        :param fromdate
        :param todate
        """

        data = dict(Action='GetFeedSubmissionList',
                    MaxCount=max_count,
                    SubmittedFromDate=fromdate,
                    SubmittedToDate=todate,)
        data.update(self.enumerate_param('FeedSubmissionIdList.Id', feedids))
        data.update(self.enumerate_param('FeedTypeList.Type.', feedtypes))
        data.update(self.enumerate_param('FeedProcessingStatusList.Status.', processingstatuses))
        return await self.make_request(data)

    async def get_submission_list_by_next_token(self, token):
        data = dict(Action='GetFeedSubmissionListByNextToken', NextToken=token)
        return await self.make_request(data)

    async def get_feed_submission_count(self, feedtypes=None, processingstatuses=None, fromdate=None, todate=None):
        data = dict(Action='GetFeedSubmissionCount',
                    SubmittedFromDate=fromdate,
                    SubmittedToDate=todate)
        data.update(self.enumerate_param('FeedTypeList.Type.', feedtypes))
        data.update(self.enumerate_param('FeedProcessingStatusList.Status.', processingstatuses))
        return await self.make_request(data)

    async def cancel_feed_submissions(self, feedids=None, feedtypes=None, fromdate=None, todate=None):
        data = dict(Action='CancelFeedSubmissions',
                    SubmittedFromDate=fromdate,
                    SubmittedToDate=todate)
        data.update(self.enumerate_param('FeedSubmissionIdList.Id.', feedids))
        data.update(self.enumerate_param('FeedTypeList.Type.', feedtypes))
        return await self.make_request(data)

    async def get_feed_submission_result(self, feedid):
        data = dict(Action='GetFeedSubmissionResult', FeedSubmissionId=feedid)
        return await self.make_request(data)


class Reports(MWS):
    """ Amazon MWS Reports API """

    ACCOUNT_TYPE = "Merchant"

    ## REPORTS ###

    async def get_report(self, report_id):
        data = dict(Action='GetReport', ReportId=report_id)
        return await self.make_request(data)

    async def get_report_count(self, report_types=(), acknowledged=None, fromdate=None, todate=None):
        data = dict(Action='GetReportCount',
                    Acknowledged=acknowledged,
                    AvailableFromDate=fromdate,
                    AvailableToDate=todate)
        data.update(self.enumerate_param('ReportTypeList.Type.', report_types))
        return await self.make_request(data)

    async def get_report_list(self, requestids=(), max_count=None, types=(), acknowledged=None,
                        fromdate=None, todate=None):
        data = dict(Action='GetReportList',
                    Acknowledged=acknowledged,
                    AvailableFromDate=fromdate,
                    AvailableToDate=todate,
                    MaxCount=max_count)
        data.update(self.enumerate_param('ReportRequestIdList.Id.', requestids))
        data.update(self.enumerate_param('ReportTypeList.Type.', types))
        return await self.make_request(data)

    async def get_report_list_by_next_token(self, token):
        data = dict(Action='GetReportListByNextToken', NextToken=token)
        return await self.make_request(data)

    async def get_report_request_count(self, report_types=(), processingstatuses=(), fromdate=None, todate=None):
        data = dict(Action='GetReportRequestCount',
                    RequestedFromDate=fromdate,
                    RequestedToDate=todate)
        data.update(self.enumerate_param('ReportTypeList.Type.', report_types))
        data.update(self.enumerate_param('ReportProcessingStatusList.Status.', processingstatuses))
        return await self.make_request(data)

    async def get_report_request_list(self, requestids=(), types=(), processingstatuses=(),
                                max_count=None, fromdate=None, todate=None):
        data = dict(Action='GetReportRequestList',
                    MaxCount=max_count,
                    RequestedFromDate=fromdate,
                    RequestedToDate=todate)
        data.update(self.enumerate_param('ReportRequestIdList.Id.', requestids))
        data.update(self.enumerate_param('ReportTypeList.Type.', types))
        data.update(self.enumerate_param('ReportProcessingStatusList.Status.', processingstatuses))
        return await self.make_request(data)

    async def get_report_request_list_by_next_token(self, token):
        data = dict(Action='GetReportRequestListByNextToken', NextToken=token)
        return await self.make_request(data)

    async def request_report(self, report_type, start_date=None, end_date=None, report_options=None, marketplaceids=()):
        data = dict(Action='RequestReport',
                    ReportType=report_type,
                    StartDate=start_date,
                    EndDate=end_date,
                    ReportOptions=report_options)
        # Added ReportOptions parameter for specific report requests.
        # ie. with this parameter we can make requests like 'RootNodesOnly = True' or 'BrowseNodeId=...'
        data.update(self.enumerate_param('MarketplaceIdList.Id.', marketplaceids))
        return await self.make_request(data)

    ## ReportSchedule ##

    async def get_report_schedule_list(self, types=()):
        data = dict(Action='GetReportScheduleList')
        data.update(self.enumerate_param('ReportTypeList.Type.', types))
        return await self.make_request(data)

    async def get_report_schedule_count(self, types=()):
        data = dict(Action='GetReportScheduleCount')
        data.update(self.enumerate_param('ReportTypeList.Type.', types))
        return await self.make_request(data)


class Orders(MWS):
    """ Amazon Orders API """

    # FIXED 2011-01-01 Orders Api is deprecated. Need to use 2013-09-01 version, uri and ns.
    URI = "/Orders/2013-09-01"
    VERSION = "2013-09-01"
    NS = '{https://mws.amazonservices.com/Orders/2013-09-01}'

    async def list_orders(self, marketplaceids, created_after=None, created_before=None, lastupdatedafter=None,
                    lastupdatedbefore=None, orderstatus=(), fulfillment_channels=(),
                    payment_methods=(), buyer_email=None, seller_orderid=None, max_results='100'):

        data = dict(Action='ListOrders',
                    CreatedAfter=created_after,
                    CreatedBefore=created_before,
                    LastUpdatedAfter=lastupdatedafter,
                    LastUpdatedBefore=lastupdatedbefore,
                    BuyerEmail=buyer_email,
                    SellerOrderId=seller_orderid,
                    MaxResultsPerPage=max_results,
                    )
        data.update(self.enumerate_param('OrderStatus.Status.', orderstatus))
        data.update(self.enumerate_param('MarketplaceId.Id.', marketplaceids))
        data.update(self.enumerate_param('FulfillmentChannel.Channel.', fulfillment_channels))
        data.update(self.enumerate_param('PaymentMethod.Method.', payment_methods))
        return await self.make_request(data)

    async def list_orders_by_next_token(self, token):
        data = dict(Action='ListOrdersByNextToken', NextToken=token)
        return await self.make_request(data)

    async def get_order(self, amazon_order_ids):
        data = dict(Action='GetOrder')
        data.update(self.enumerate_param('AmazonOrderId.Id.', amazon_order_ids))
        return await self.make_request(data)

    async def list_order_items(self, amazon_order_id):
        data = dict(Action='ListOrderItems', AmazonOrderId=amazon_order_id)
        return await self.make_request(data)

    async def list_order_items_by_next_token(self, token):
        data = dict(Action='ListOrderItemsByNextToken', NextToken=token)
        return await self.make_request(data)


class Products(MWS):
    """ Amazon MWS Products API """

    URI = '/Products/2011-10-01'
    VERSION = '2011-10-01'
    NS = '{http://mws.amazonservices.com/schema/Products/2011-10-01}'

    async def list_matching_products(self, marketplaceid, query, contextid=None):
        """ Returns a list of products and their attributes, ordered by
            relevancy, based on a search query that you specify.
            Your search query can be a phrase that describes the product
            or it can be a product identifier such as a UPC, EAN, ISBN, or JAN.
            :param marketplaceid
            :param query
            :param contextid
        """
        data = dict(Action='ListMatchingProducts',
                    MarketplaceId=marketplaceid,
                    Query=query,
                    QueryContextId=contextid)
        return await self.make_request(data)

    async def get_matching_product(self, marketplaceid, asins):
        """ Returns a list of products and their attributes, based on a list of
            ASIN values that you specify.
            :param marketplaceid
            :param asins
        """
        data = dict(Action='GetMatchingProduct', MarketplaceId=marketplaceid)
        data.update(self.enumerate_param('ASINList.ASIN.', asins))
        return await self.make_request(data)

    async def get_matching_product_for_id(self, marketplaceid, _type, ids):
        """ Returns a list of products and their attributes, based on a list of
            product identifier values (ASIN, SellerSKU, UPC, EAN, ISBN, GCID  and JAN)
            The identifier type is case sensitive.
            Added in Fourth Release, API version 2011-10-01
            :param marketplaceid
            :param _type
            :param ids
        """
        data = dict(Action='GetMatchingProductForId',
                    MarketplaceId=marketplaceid,
                    IdType=_type)
        data.update(self.enumerate_param('IdList.Id.', ids))
        return await self.make_request(data)

    async def get_competitive_pricing_for_sku(self, marketplaceid, skus):
        """ Returns the current competitive pricing of a product,
            based on the SellerSKU and MarketplaceId that you specify.
            :param marketplaceid
            :param skus
        """
        data = dict(Action='GetCompetitivePricingForSKU', MarketplaceId=marketplaceid)
        data.update(self.enumerate_param('SellerSKUList.SellerSKU.', skus))
        return await self.make_request(data)

    async def get_competitive_pricing_for_asin(self, marketplaceid, asins):
        """ Returns the current competitive pricing of a product,
            based on the ASIN and MarketplaceId that you specify.
            :param marketplaceid
            :param asins
        """
        data = dict(Action='GetCompetitivePricingForASIN', MarketplaceId=marketplaceid)
        data.update(self.enumerate_param('ASINList.ASIN.', asins))
        return await self.make_request(data)

    async def get_lowest_offer_listings_for_sku(self, marketplaceid, skus, condition="Any", excludeme="False"):
        data = dict(Action='GetLowestOfferListingsForSKU',
                    MarketplaceId=marketplaceid,
                    ItemCondition=condition,
                    ExcludeMe=excludeme)
        data.update(self.enumerate_param('SellerSKUList.SellerSKU.', skus))
        return await self.make_request(data)

    async def get_lowest_offer_listings_for_asin(self, marketplaceid, asins, condition="Any", excludeme="False"):
        data = dict(Action='GetLowestOfferListingsForASIN',
                    MarketplaceId=marketplaceid,
                    ItemCondition=condition,
                    ExcludeMe=excludeme)
        data.update(self.enumerate_param('ASINList.ASIN.', asins))
        return await self.make_request(data)

    async def get_lowest_priced_offers_for_sku(self, marketplaceid, sku, condition="New", excludeme="False"):
        data = dict(Action='GetLowestPricedOffersForSKU',
                    MarketplaceId=marketplaceid,
                    SellerSKU=sku,
                    ItemCondition=condition,
                    ExcludeMe=excludeme)
        return await self.make_request(data)

    async def get_lowest_priced_offers_for_asin(self, marketplaceid, asin, condition="New", excludeme="False"):
        data = dict(Action='GetLowestPricedOffersForASIN',
                    MarketplaceId=marketplaceid,
                    ASIN=asin,
                    ItemCondition=condition,
                    ExcludeMe=excludeme)
        return await self.make_request(data)

    async def get_product_categories_for_sku(self, marketplaceid, sku):
        data = dict(Action='GetProductCategoriesForSKU',
                    MarketplaceId=marketplaceid,
                    SellerSKU=sku)
        return await self.make_request(data)

    async def get_product_categories_for_asin(self, marketplaceid, asin):
        data = dict(Action='GetProductCategoriesForASIN',
                    MarketplaceId=marketplaceid,
                    ASIN=asin)
        return await self.make_request(data)

    async def get_my_price_for_sku(self, marketplaceid, skus, condition=None):
        data = dict(Action='GetMyPriceForSKU',
                    MarketplaceId=marketplaceid,
                    ItemCondition=condition)
        data.update(self.enumerate_param('SellerSKUList.SellerSKU.', skus))
        return await self.make_request(data)

    async def get_my_price_for_asin(self, marketplaceid, asins, condition=None):
        data = dict(Action='GetMyPriceForASIN',
                    MarketplaceId=marketplaceid,
                    ItemCondition=condition)
        data.update(self.enumerate_param('ASINList.ASIN.', asins))
        return await self.make_request(data)


class Sellers(MWS):
    """ Amazon MWS Sellers API """

    URI = '/Sellers/2011-07-01'
    VERSION = '2011-07-01'
    NS = '{http://mws.amazonservices.com/schema/Sellers/2011-07-01}'

    async def list_marketplace_participations(self):
        """
            Returns a list of marketplaces a seller can participate in and
            a list of participations that include seller-specific information in that marketplace.
            The operation returns only those marketplaces where the seller's account is in an active state.
        """

        data = dict(Action='ListMarketplaceParticipations')
        return await self.make_request(data)

    async def list_marketplace_participations_by_next_token(self, token):
        """
            Takes a "NextToken" and returns the same information as "list_marketplace_participations".
            Based on the "NextToken".
        """
        data = dict(Action='ListMarketplaceParticipations', NextToken=token)
        return await self.make_request(data)


#### Fulfillment APIs ####


class InboundShipments(MWS):
    URI = "/FulfillmentInboundShipment/2010-10-01"
    VERSION = '2010-10-01'

    # To be completed


class Inventory(MWS):
    """ Amazon MWS Inventory Fulfillment API """

    URI = '/FulfillmentInventory/2010-10-01'
    VERSION = '2010-10-01'
    NS = "{http://mws.amazonaws.com/FulfillmentInventory/2010-10-01}"

    async def list_inventory_supply(self, skus=(), datetime=None, response_group='Basic'):
        """ Returns information on available inventory
            :param skus
            :param datetime
            :param response_group
        """

        data = dict(Action='ListInventorySupply',
                    QueryStartDateTime=datetime,
                    ResponseGroup=response_group,
                    )
        data.update(self.enumerate_param('SellerSkus.member.', skus))
        return await self.make_request(data, "POST")

    async def list_inventory_supply_by_next_token(self, token):
        data = dict(Action='ListInventorySupplyByNextToken', NextToken=token)
        return await self.make_request(data, "POST")


class OutboundShipments(MWS):
    URI = "/FulfillmentOutboundShipment/2010-10-01"
    VERSION = "2010-10-01"
    # To be completed


class Recommendations(MWS):

    """ Amazon MWS Recommendations API """

    URI = '/Recommendations/2013-04-01'
    VERSION = '2013-04-01'
    NS = "{https://mws.amazonservices.com/Recommendations/2013-04-01}"

    async def get_last_updated_time_for_recommendations(self, marketplaceid):
        """
        Checks whether there are active recommendations for each category for the given marketplace, and if there are,
        returns the time when recommendations were last updated for each category.
        :param marketplaceid
        """

        data = dict(Action='GetLastUpdatedTimeForRecommendations',
                    MarketplaceId=marketplaceid)
        return await self.make_request(data, "POST")

    async def list_recommendations(self, marketplaceid, recommendationcategory=None):
        """
        Returns your active recommendations for a specific category or for all categories for a specific marketplace.
        :param marketplaceid
        :param recommendationcategory
        """

        data = dict(Action="ListRecommendations",
                    MarketplaceId=marketplaceid,
                    RecommendationCategory=recommendationcategory)
        return await self.make_request(data, "POST")

    async def list_recommendations_by_next_token(self, token):
        """
        Returns the next page of recommendations using the NextToken parameter.
        :param token
        """

        data = dict(Action="ListRecommendationsByNextToken",
                    NextToken=token)
        return await self.make_request(data, "POST")


class MerchantFulfillment(MWS):

    """ Amazon MWS Merchant Fulfillment API """

    ACCOUNT_TYPE = "Merchant"

    URI = 'MerchantFulfillment/2015-06-01'
    VERSION = '2015-06-01'
    NS = "{https://mws.amazonservices.com/MerchantFulfillment/2015-06-01}"

    async def get_eligible_shipping_services(self, shipment_request_details_dict, order_item_list):
        """
        Returns a list of shipping service offers.
        :param shipment_request_details_dict     must have these elements
        ( amazon_order_id, length, width, height, height_unit, weight, weight_unit, name, address_line_1, city,
         postal_code, country_code, email, phone, delivery_experience, carrier_will_pickup, currency_code, amount )
        :param order_item_list   's components must be a dict { order_item_id , quantity }
        """

        data = dict(Action="GetEligibleShippingService")

        # FIXME these all were not best practice but all of these parameters required.
        # FIXME Maybe, I can find much pythonic way later.
        data.update({"ShipmentRequestDetails.AmazonOrderId": shipment_request_details_dict['amazon_order_id']})
        data.update({"ShipmentRequestDetails.PackageDimensions.Length": shipment_request_details_dict['length']})
        data.update({"ShipmentRequestDetails.PackageDimensions.Width": shipment_request_details_dict['width']})
        data.update({"ShipmentRequestDetails.PackageDimensions.Height": shipment_request_details_dict['height']})
        data.update({"ShipmentRequestDetails.PackageDimensions.Unit": shipment_request_details_dict['height_unit']})
        data.update({"ShipmentRequestDetails.Weight.Value": shipment_request_details_dict['weight']})
        data.update({"ShipmentRequestDetails.Weight.Unit": shipment_request_details_dict['weight_unit']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.Name": shipment_request_details_dict['name']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.AddressLine1": shipment_request_details_dict['address_line_1']})
        if 'address_line_2' in shipment_request_details_dict:
            data.update({"ShipmentRequestDetails.ShipFromAddress.AddressLine1": shipment_request_details_dict['address_line_2']})
        if 'address_line_3' in shipment_request_details_dict:
            data.update({"ShipmentRequestDetails.ShipFromAddress.AddressLine1": shipment_request_details_dict['address_line_3']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.City": shipment_request_details_dict['city']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.StateOrProvinceCode": shipment_request_details_dict['state_or_province_code']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.PostalCode": shipment_request_details_dict['postal_code']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.CountryCode": shipment_request_details_dict['country_code']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.Email": shipment_request_details_dict['email']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.Phone": shipment_request_details_dict['phone']})
        data.update({"ShipmentRequestDetails.ShippingServiceOptions.DeliveryExperience": shipment_request_details_dict['delivery_experience']})
        data.update({"ShipmentRequestDetails.ShippingServiceOptions.CarrierWillPickUp": shipment_request_details_dict['carrier_will_pickup']})
        data.update({"ShipmentRequestDetails.ShippingServiceOptions.DeclaredValue.CurrencyCode": shipment_request_details_dict['currency_code']})
        data.update({"ShipmentRequestDetails.ShippingServiceOptions.DeclaredValue.Amount": shipment_request_details_dict['amount']})
        counter = 1
        for order_item_dict in order_item_list:
            data.update({"ShipmentRequestDetails.ItemList.Item.{}.OrderItemId".format(counter): order_item_dict['order_item_id']})
            data.update({"ShipmentRequestDetails.ItemList.Item.{}.Quantity".format(counter): order_item_dict['quantity']})
            counter += 1

        return await self.make_request(data)

    async def create_shipment(self, shipping_service_id, shipment_request_details_dict, order_item_list):
        """
        Purchases shipping and returns a shipping label.

        The CreateShipment operation purchases shipping and returns PNG or PDF document data for a shipping label.
        Amazon compresses the document data before returning it as a Base64-encoded string. To obtain the actual PNG or
        PDF document, decode the Base64-encoded string, save it as a binary file with a “.gzip” extension, and then
        extract the PNG or PDF file from the GZIP file. Alternatively, you can obtain the label from the decoded data
        by using the GZIP decompression functionality included in most programming languages. This operation also
        returns a Base64-encoded MD5 hash to validate the document data.
        :param shipping_service_id
        :param shipment_request_details_dict     must have these elements
        ( amazon_order_id, length, width, height, height_unit, weight, weight_unit, name, address_line_1, city,
         postal_code, country_code, email, phone, delivery_experience, carrier_will_pickup, currency_code, amount )
        :param order_item_list   's components must be a dict { order_item_id , quantity }
        """

        data = dict(Action="CreateShipment",
                    ShippingServiceId=shipping_service_id)

        # FIXME these all were not best practice but all of these parameters required.
        # FIXME Maybe, I can find much pythonic way later.
        data.update({"ShipmentRequestDetails.AmazonOrderId": shipment_request_details_dict['amazon_order_id']})
        data.update({"ShipmentRequestDetails.PackageDimensions.Length": shipment_request_details_dict['length']})
        data.update({"ShipmentRequestDetails.PackageDimensions.Width": shipment_request_details_dict['width']})
        data.update({"ShipmentRequestDetails.PackageDimensions.Height": shipment_request_details_dict['height']})
        data.update({"ShipmentRequestDetails.PackageDimensions.Unit": shipment_request_details_dict['height_unit']})
        data.update({"ShipmentRequestDetails.Weight.Value": shipment_request_details_dict['weight']})
        data.update({"ShipmentRequestDetails.Weight.Unit": shipment_request_details_dict['weight_unit']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.Name": shipment_request_details_dict['name']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.AddressLine1": shipment_request_details_dict['address_line_1']})
        if 'address_line_2' in shipment_request_details_dict:
            data.update({"ShipmentRequestDetails.ShipFromAddress.AddressLine1": shipment_request_details_dict['address_line_2']})
        if 'address_line_3' in shipment_request_details_dict:
            data.update({"ShipmentRequestDetails.ShipFromAddress.AddressLine1": shipment_request_details_dict['address_line_3']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.City": shipment_request_details_dict['city']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.StateOrProvinceCode": shipment_request_details_dict['state_or_province_code']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.PostalCode": shipment_request_details_dict['postal_code']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.CountryCode": shipment_request_details_dict['country_code']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.Email": shipment_request_details_dict['email']})
        data.update({"ShipmentRequestDetails.ShipFromAddress.Phone": shipment_request_details_dict['phone']})
        data.update({"ShipmentRequestDetails.ShippingServiceOptions.DeliveryExperience": shipment_request_details_dict['delivery_experience']})
        data.update({"ShipmentRequestDetails.ShippingServiceOptions.CarrierWillPickUp": shipment_request_details_dict['carrier_will_pickup']})
        data.update({"ShipmentRequestDetails.ShippingServiceOptions.DeclaredValue.CurrencyCode": shipment_request_details_dict['currency_code']})
        data.update({"ShipmentRequestDetails.ShippingServiceOptions.DeclaredValue.Amount": shipment_request_details_dict['amount']})
        counter = 1
        for order_item_dict in order_item_list:
            data.update({"ShipmentRequestDetails.ItemList.Item.{}.OrderItemId".format(counter): order_item_dict['order_item_id']})
            data.update({"ShipmentRequestDetails.ItemList.Item.{}.Quantity".format(counter): order_item_dict['quantity']})
            counter += 1

        return await self.make_request(data, "POST")

    async def get_shipment(self, shipment_id):
        """
        Returns an existing shipment for a given identifier.
        :param shipment_id
        """

        data = dict(Action="GetShipment",
                    ShipmentId=shipment_id)
        return await self.make_request(data)

    async def cancel_shipment(self, shipment_id):
        """
        Cancels an existing shipment.
        :param shipment_id
        """

        data = dict(Action="CancelShipment",
                    ShipmentId=shipment_id)
        return await self.make_request(data)
