/* CVS Header
   $Id$
   $Log$
*/

package org.guanxi;

import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.util.Util;
import com.xpn.xwiki.web.XWikiRequest;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.objects.BaseObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ecs.xhtml.map;
import org.securityfilter.realm.SimplePrincipal;

import java.security.Principal;
import java.util.HashMap;
import java.util.Enumeration;
import java.util.Map;

public class GuanxiAuthenticator extends XWikiAuthServiceImpl {
  private static final Log log = LogFactory.getLog(GuanxiAuthenticator.class);

  public XWikiUser checkAuth(XWikiContext context) throws XWikiException {
    return super.checkAuth(context);
  }

  public void showLogin(XWikiContext context) throws XWikiException {
    super.showLogin(context);
  }

  public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException {
    Principal principal = null;

    XWikiRequest req = context.getRequest();
    String s = req.getParameter("xredirect");

    Enumeration e = req.getHttpServletRequest().getHeaderNames();
    while (e.hasMoreElements()) {
      String name = (String)e.nextElement();
      if (name.startsWith("HTTP_")) {
        String value = req.getHttpServletRequest().getHeader(name);
        System.out.println(name + " --> " + value + "<br>");
      }
    }

    principal = createUserFromAttributes(context);

    return principal;
  }

  private Principal createUserFromAttributes(XWikiContext context) throws XWikiException {
    try {
      BaseClass baseclass = context.getWiki().getUserClass(context);

      String[] parts = context.getRequest().getHttpServletRequest().getHeader("HTTP_cn").split(";");
      String userIDAttribute = parts[0];
      String fullwikiname = "XWiki." + userIDAttribute;

      XWikiDocument doc = context.getWiki().getDocument(fullwikiname, context);
      /*
      if (!doc.isNew()) {
        return getUserPrincipal(fullwikiname, context);
      }
      */

      Map map = new HashMap();
      map.put("active", "1");
      BaseObject newobject = (BaseObject)baseclass.fromMap(map, context);
      newobject.setName(fullwikiname);
      doc.addObject(baseclass.getName(), newobject);
      doc.setParent("");
      doc.setContent("#includeForm(\"XWiki.XWikiUserTemplate\")");

      context.getWiki().ProtectUserPage(context, fullwikiname, "edit", doc);

      context.getWiki().saveDocument(doc, null, context);

      context.getWiki().SetUserDefaultGroup(context, fullwikiname);

      return getUserPrincipal(fullwikiname, context);
    }
    catch(Exception e) {
      return null;
    }
  }

  private Principal getUserPrincipal(String susername, XWikiContext context) {
      Principal principal = null;

      // First we check in the local database
      try {
          String user = findUser(susername, context);
          if (user!=null) {
              principal = new SimplePrincipal(user);
          }
      } catch (Exception e) {}

      if (context.isVirtual()) {
          if (principal==null) {
              // Then we check in the main database
              String db = context.getDatabase();
              try {
                  context.setDatabase(context.getWiki().getDatabase());
                  try {
                      String user = findUser(susername, context);
                      if (user!=null)
                          principal = new SimplePrincipal(context.getDatabase() + ":" + user);
                  } catch (Exception e) {}
              } finally {
                  context.setDatabase(db);
              }
          }
      }
      return principal;
  }
}