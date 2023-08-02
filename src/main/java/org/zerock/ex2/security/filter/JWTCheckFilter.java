package org.zerock.ex2.security.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.ex2.util.JWTUtil;

import com.google.gson.Gson;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class JWTCheckFilter extends OncePerRequestFilter {

    // true이면 filter 를 타지 않고, false면 filter를 타야만 된다.
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException{
        
        // Preflight 일때 제외시켜줘야된다.
        if(request.getMethod().equals("OPTIONS")){
            return true;
        }

        // /api/todo/list /api/member/login
        String path = request.getRequestURI();

        if(path.equals("/api/member/login")){
            return true;
        }

        return false;


    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request, 
        HttpServletResponse response, 
        FilterChain filterChain)
            throws ServletException, IOException {
       
        log.info("--------------doFilterInternal------------------");

        log.info("--------------doFilterInternal------------------");

        // 필터 통과후 다음 필터나 컨트롤러등을 호출 Security에서 잡아야된다
         String authHeaderStr = request.getHeader("Authorization");
 
    try {
      //Bearer accestoken...
      String accessToken = authHeaderStr.substring(7);
      Map<String, Object> claims = JWTUtil.validateToken(accessToken);
 
      log.info("JWT claims: " + claims);
 
      filterChain.doFilter(request, response);
 
    }catch(Exception e){
 
      log.error("JWT Check Error..............");
      log.error(e.getMessage());
 
      Gson gson = new Gson();
      String msg = gson.toJson(Map.of("error", "ERROR_ACCESS_TOKEN"));
 
      response.setContentType("application/json");
      PrintWriter printWriter = response.getWriter();
      printWriter.println(msg);
      printWriter.close();


    }
    
}
}