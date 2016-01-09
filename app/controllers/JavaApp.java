package controllers;

import org.apache.shiro.SecurityUtils;
import play.Logger;
import play.mvc.Controller;
import play.mvc.Result;

/**
 * Similar to scala Application, demonstrates use in Java
 */
public class JavaApp extends Controller {

    public static Result index() {
        if (!SecurityUtils.getSubject().isPermitted("read")){
            Logger.error("NOT PERMITTED");
        }
        if (!SecurityUtils.getSubject().isAuthenticated()){
            Logger.error("NOT AUTHENTICATED");
        }
        return ok("Hello Shiro!");
    }
}
