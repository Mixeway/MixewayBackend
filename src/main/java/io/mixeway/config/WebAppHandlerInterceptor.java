package io.mixeway.config;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

public class WebAppHandlerInterceptor extends HandlerInterceptorAdapter {
    private final Semaphore semaphore;
    private final long waitTime;
    WebAppHandlerInterceptor() {
        // Hardcode this values or inject through spring as preferred.
        semaphore = new Semaphore(1);
        waitTime = 2;
    }
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        try {
            boolean acquired = semaphore.tryAcquire(1, waitTime, TimeUnit.SECONDS);
            if (!acquired) {
                Thread.sleep(500);

                //TODO Do something with the response or keep waiting or whatever
            }
        } catch (InterruptedException e) {
            // Do something with this exception. Write custom message to response and then return false.
            // TODO write custom message to response i.e interrupted or something
            return false;
        }
        return super.preHandle(request, response, handler);
    }

    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           ModelAndView modelAndView) throws Exception {
        semaphore.release();
        super.postHandle(request, response, handler, modelAndView);
    }

}
