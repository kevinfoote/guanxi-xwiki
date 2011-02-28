/* CVS Header
   $Id$
   $Log$
*/

package org.guanxi;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.web.XWikiAction;

public class ShibbLoginAction extends XWikiAction {
  public String render(XWikiContext context) throws XWikiException {
        return "shibblogin";
  }
}
