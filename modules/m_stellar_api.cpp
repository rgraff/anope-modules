#include "module.h"
#include "modules/os_forbid.h"
#include "modules/httpd.h"
#include "third/tags.h"
#include "third/json_api.h"
#include "third/m_token_auth.h"

class APIRequest
	: public HTTPMessage
{
 public:
  typedef std::map<Anope::string, Anope::string> HeaderMap;
	typedef std::map<Anope::string, Anope::string> ParamMap;
	typedef Anope::string ip_t;

 private:
	const Anope::string client_authorization;
	const ip_t client_ip;
  
 public:

	APIRequest(const APIRequest& other)
		: HTTPMessage(other)
		, client_authorization(other.client_authorization)
		, client_ip(other.client_ip)
  {
	}

	APIRequest(const HTTPMessage& message, const ip_t& ClientIP)
		: HTTPMessage(message)
		, client_authorization(GetHeader("Authorization"))
		, client_ip(ClientIP)
	{
	}

	const Anope::string& getClientAuthorization() const
	{
		return client_authorization;
	}

	const ip_t& getClientIp() const
	{
		return client_ip;
	}

	bool IsValid(Anope::string secretkey) const
	{
    if (client_authorization.empty() || client_ip.empty())
      return false;

    return (secretkey == client_authorization);
	}

  // Header access helpers
	bool HasHeader(const HeaderMap::key_type& name) const
	{
		return headers.find(name) != headers.end();
	}

	bool GetHeader(const HeaderMap::key_type& name, HeaderMap::mapped_type& value) const
	{
		HeaderMap::const_iterator it = headers.find(name);

		if (it == headers.end())
			return false;

		value = it->second;

		return true;
	}
  
  HeaderMap::mapped_type GetHeader(const HeaderMap::key_type& name) const
	{
		HeaderMap::mapped_type value;
		GetHeader(name, value);
		return value;
	}

  // Parameter access helpers
	bool HasParameter(const ParamMap::key_type& name) const
	{
		return post_data.find(name) != post_data.end();
	}

	bool GetParameter(const ParamMap::key_type& name, ParamMap::mapped_type& value) const
	{
		ParamMap::const_iterator it = post_data.find(name);

		if (it == post_data.end())
			return false;

		value = it->second;

		return true;
	}

	ParamMap::mapped_type GetParameter(const ParamMap::key_type& name) const
	{
		ParamMap::mapped_type value;
		GetParameter(name, value);
		return value;
	}
};

class APIEndpoint;

class APILogger
	: public Log
{
 public:
	APILogger(const APIEndpoint& endpoint, const APIRequest& request);
};

class APIEndpoint
	: public JsonAPIEndpoint
{
	typedef std::set<Anope::string> RequiredParams;
	RequiredParams required_params;
  const Anope::string secretkey

 public:
	Module* creator;

	APIEndpoint(Module* Creator, const Anope::string& u)
		: JsonAPIEndpoint(u)
		, creator(Creator)
	{
	}

	void AddRequiredParam(const Anope::string& name)
	{
		required_params.insert(name);
	}

	Anope::string GetEndpointID() const
	{
		return this->GetURL().substr(1);
	}

	bool OnRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client,
				   HTTPMessage& message, HTTPReply& reply) anope_override
	{
		APIRequest request(message, client->GetIP());

		if (!request.IsValid(secretkey))
		{
			reply.error = HTTP_BAD_REQUEST;
      
      JsonObject error;
			error["id"] = "unauthorized";
			error["message"] = "Request unauthorized";

			JsonObject responseObj;
			responseObj["status"] = "error";
			responseObj["error"] = error;

			reply.Write(responseObj.str());

		  APILogger(*this, request) << "UNAUTHORIZED ";

			return true;
		}

		JsonArray missing;

		for (RequiredParams::const_iterator it = required_params.begin(); it != required_params.end(); ++it)
		{
			if (request.GetParameter(*it).empty())
				missing.push_back(*it);
		}

		if (!missing.empty())
		{
			reply.error = HTTP_BAD_REQUEST;

			JsonObject error;
			error["id"] = "missing_parameters";
			error["message"] = "Missing required request parameters";
			error["parameters"] = missing;

			JsonObject responseObj;
			responseObj["status"] = "error";
			responseObj["error"] = error;

			reply.Write(responseObj.str());

      APILogger(*this, request) << "ERROR missing parameters";

			return true;
		}

		APILogger(*this, request) << "Request received";
		JsonObject responseObject, errorObject;

		if (!HandleRequest(request, responseObject, errorObject))
		{
			responseObject["error"] = errorObject;
			responseObject["status"] = "error";

			APILogger(*this, request) << "Error: " << errorObject["id"].str();
		}
		else
		{
			responseObject["status"] = "ok";
		}
		reply.Write(responseObject.str());

		return true;
	}

	virtual bool HandleRequest(HTTPProvider* provider, const Anope::string& string, HTTPClient* client,
							   APIRequest& request, HTTPReply& reply) = 0;

	virtual void DoReload(Configuration::Conf* conf)
	{
    Configuration::Block* block = conf->GetModule("m_stellar_api");
    secretkey = << block->Get<const Anope::string>("secretkey", "");
	}
};

APILogger::APILogger(const APIEndpoint& endpoint, const APIRequest& request)
	: Log(LOG_NORMAL, endpoint.GetEndpointID())
{
	*this << "API: " << category << " from " << request.getClientIp() << ": ";
}



/* ****************************************************************************
 * * 
 * *            END POINTS
 * *
 * ****************************************************************************
 */

class AuthorizeEndpoint
  : public APIEndpoint
{
 private:
	ServiceReference<ForbidService> forbidService;

 public:
  AuthorizeEndpoint(Module* Creator)
		: APIEndpoint(Creator, "authorize")
		, forbidService("ForbidService", "forbid")
	{
		AddRequiredParam("username");
	}

  Anope::string GetToken(APIRequest& request, NickCore* nc, const Anope::string& token_name)
  {
    // Get our token list
    AuthTokenList* tokens = GetTokenList(nc, true);
		if (!tokens)
      return "tokens_disabled";

    AuthToken* token;
    token = tokens->FindToken(token_name);
    if (!token)
    {
      token = tokens->NewToken(token_name);
      APILogger(*this, request) << "token generated for '" << nc->display << "'";
    }
    else 
    {
      APILogger(*this, request) << "token found for '" << nc->display << "'";
    }

    return token->GetToken();
  }

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
		Anope::string username = request.GetParameter("username");

    // Verify nick is not forbidden from reg/usage
    if (forbidService)
    {
      ForbidData* nickforbid = forbidService->FindForbid(username, FT_NICK);
      ForbidData* regforbid = forbidService->FindForbid(username, FT_REGISTER);
      if (nickforbid || regforbid)
      {
        errorObject["id"] = "forbidden_user";
        errorObject["message"] = "This nickname is forbidden from registration";
        return false;
      }
    }

    // Find our NickAlias from our username
    NickAlias* na;
    NickCore* nc;

    na = NickAlias::Find(username);
    if (na)
    {
      nc = na->nc;
    }
    else
    {
  		nc = new NickCore(username);
	  	na = new NickAlias(username, nc);
      APILogger(*this, request) << "Account created for '" << nc->display << "'";
    }

    // Generate a token if requested
    if (request.HasParameter("token"))
    {
      Anope::string tokenName = request.GetParameter("token");
      responseObject["token"] = GetToken(request, nc, tokenName);
    }

    // Broadcast out the tags
		TagList* list = nc->Require<TagList>("taglist");
    list->Broadcast(nc);
    responseObject["tags"] = list->AsJsonObject();

		return true;
	}
};

class AddTagEndpoint
	: public APIEndpoint
{
 public:
	AddTagEndpoint(Module* Creator)
		: APIEndpoint(Creator, "tags/add")
	{
		AddRequiredParam("username");
		AddRequiredParam("name");
		AddRequiredParam("value");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
    Anope::string username = request.GetParameter("username");

    NickAlias* na;
    NickCore* nc;

    na = NickAlias::Find(username);
    if (na)
    {
      nc = na->nc;
    }
    else
    {
				errorObject["id"] = "invalid_username";
				errorObject["message"] = "Username does not exist";	
				return false;
    }

		TagList* list = nc->Require<TagList>("taglist");

		Anope::string tagname = request.GetParameter("name");
    Anope::string tagvalue = request.GetParameter("value");	

    bool result = list->SetTag(nc, tagname, tagvalue);
    if (result) {
      list->Broadcast(nc);
    }
    else
    {
			errorObject["id"] = "invalid_tag";
			errorObject["message"] = "Failed to add tag";	
			return false;
    }

    responseObject["tags"] = list->AsJsonObject();

    return true;
	}
};

class DeleteTagEndpoint
	: public APIEndpoint
{
 public:
	DeleteTagEndpoint(Module* Creator)
		: APIEndpoint(Creator, "tags/delete")
	{
		AddRequiredParam("username");
		AddRequiredParam("name");
	}

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
    Anope::string username = request.GetParameter("username");

		NickAlias* na;
    NickCore* nc;

    na = NickAlias::Find(username);
    if (na)
    {
      nc = na->nc;
    }
    else
    {
				errorObject["id"] = "invalid_username";
				errorObject["message"] = "Username does not exist";	
				return false;
    }
    
    Anope::string tagname = request.GetParameter("name");
		TagList* list = nc->Require<TagList>("taglist");
    bool result = list->DelTag(tagname);
    if (result)
    {
      list->Broadcast(nc);
    }
    else
    {
			// We can't delete a non-existent tag.
			errorObject["id"] = "no_tag";
			errorObject["message"] = "No matching tag found.";	
			return false;
    }

    responseObject["tags"] = list->AsJsonObject();

		return true;
	}
};

class ListTagsEndpoint
	: public APIEndpoint
{
 public:
	ListTagsEndpoint(Module* Creator)
		: APIEndpoint(Creator, "tags")
	{
    AddRequiredParam("username");
  }

	bool HandleRequest(APIRequest& request, JsonObject& responseObject, JsonObject& errorObject) anope_override
	{
    Anope::string username = request.GetParameter("username");
    bool clear = request.HasParameter("clear");

		NickAlias* na;
    NickCore* nc;

    na = NickAlias::Find(username);
    if (na)
    {
      nc = na->nc;
    }
    else
    {
				errorObject["id"] = "invalid_username";
				errorObject["message"] = "Username does not exist";	
				return false;
    }
  	
    TagList* list = nc->Require<TagList>("taglist");
    if (clear) 
      list->Clear();

		responseObject["tags"] = list->AsJsonObject();
		return true;
	}
};

class StellarApiModule
	: public Module
{
	ServiceReference<HTTPProvider> httpd;
  ServiceReference<ForbidService> forbidService;

	ExtensibleItem<TagList> taglist;
	Serialize::Type tagentry_type;
	AddTagEndpoint addtag;
	DeleteTagEndpoint deltag;
	ListTagsEndpoint listtags;
  AuthorizeEndpoint authorize;

	typedef std::vector<APIEndpoint*> PageList;
	PageList pages;

 public:
	StellarApiModule(const Anope::string& modname, const Anope::string& creator)
		: Module(modname, creator, THIRD)
		, taglist(this, "taglist")
		, tagentry_type("TagEntry", TagEntry::Unserialize)
		, addtag(this)
		, deltag(this)
		, listtags(this)
    , authorize(this)
	{
		this->SetAuthor("linuxdaemon"); // derivitive of the work of linuxdaemon & others
		this->SetVersion("0.1");

		pages.push_back(&addtag);
		pages.push_back(&deltag);
		pages.push_back(&listtags);
    pages.push_back(&authorize);
	}

	void RegisterPages()
	{
		if (!httpd)
			return;

		for (PageList::iterator it = pages.begin(); it != pages.end(); ++it)
			httpd->RegisterPage(*it);
	}

	void UnregisterPages()
	{
		if (!httpd)
			return;

		for (PageList::iterator it = pages.begin(); it != pages.end(); ++it)
			httpd->UnregisterPage(*it);
	}

	~StellarApiModule() anope_override
	{
		UnregisterPages();
	}

	void OnUserLogin(User* u) anope_override
	{
		TagList* list = u->Account()->GetExt<TagList>("taglist");
		if (list)
			list->Broadcast(u->Account());
	}

	void OnReload(Configuration::Conf* conf) anope_override
	{
		Configuration::Block* block = conf->GetModule(this);
		UnregisterPages();

    const Anope::string secret_key = block->Get<const Anope::string>("secretkey", "");
    if (secret_key.empty())
			throw ConfigException("Unable to find secretkey in module configuration");    

		const Anope::string provider = block->Get<const Anope::string>("server", "httpd/main");
		this->httpd = ServiceReference<HTTPProvider>("HTTPProvider", provider);
		if (!httpd)
			throw ConfigException("Unable to find http reference, is m_httpd loaded?");

		RegisterPages();

		for (PageList::iterator it = pages.begin(); it != pages.end(); ++it)
			(*it)->DoReload(conf);
	}
};

MODULE_INIT(StellarApiModule)
