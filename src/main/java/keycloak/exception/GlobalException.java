package keycloak.exception;

import keycloak.payload.response.APIResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.TypeMismatchException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.nio.file.AccessDeniedException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
@ConditionalOnMissingBean(GlobalException.class)
public class GlobalException {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<APIResponse<Object>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error -> {
            String field = error.getField();
            String message = error.getDefaultMessage();
            errors.put(field, message);
        });

        log.warn("Validation failed: {}", errors);

        APIResponse<Object> response = APIResponse.builder()
                .message("Validation Failed")
                .result(errors)
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<APIResponse<Object>> handleIllegalArgumentExceptions(IllegalArgumentException ex) {
        log.warn("IllegalArgumentException: {}", ex.getMessage());

        APIResponse<Object> response = APIResponse.builder()
                .message("Request JSON invalid! (Argument null or blank)")
                .result(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<APIResponse<Object>> handlerHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
        log.warn("HttpMessageNotReadableException: {}", ex.getMessage());

        APIResponse<Object> response = APIResponse.builder()
                .message("Request JSON invalid!")
                .result(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<APIResponse<Object>> handleNoHandlerFoundException(NoHandlerFoundException ex) {
        log.warn("NoHandlerFoundException: {}", ex.getMessage());

        APIResponse<Object> response = APIResponse.builder()
                .message("URL doesn't exist")
                .result(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<APIResponse<Object>> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException ex) {
        log.warn("HttpRequestMethodNotSupportedException: {}", ex.getMessage());

        APIResponse<Object> response = APIResponse.builder()
                .message("Wrong HTTP method")
                .result(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, HttpStatus.METHOD_NOT_ALLOWED);
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<APIResponse<Object>> handlerHttpMediaTypeNotSupportedException(HttpMediaTypeNotSupportedException ex) {
        log.warn("HttpMediaTypeNotSupportedException: {}", ex.getMessage());

        APIResponse<Object> response = APIResponse.builder()
                .message("Unsupported or missing Content-Type")
                .result(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, HttpStatus.UNSUPPORTED_MEDIA_TYPE);
    }

    @ExceptionHandler(TypeMismatchException.class)
    public ResponseEntity<APIResponse<Object>> handlerTypeMismatchException(TypeMismatchException ex) {
        log.warn("TypeMismatchException: {}", ex.getMessage());

        APIResponse<Object> response = APIResponse.builder()
                .message("Wrong data type argument")
                .result(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MissingPathVariableException.class)
    public ResponseEntity<APIResponse<Object>> handlerMissingPathVariableException(MissingPathVariableException ex) {
        log.warn("MissingPathVariableException: {}", ex.getMessage());

        APIResponse<Object> response = APIResponse.builder()
                .message("Missing path variable")
                .result(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<APIResponse<Object>> handlerAccessDeniedException(AccessDeniedException ex) {
        log.warn("AccessDeniedException: {}", ex.getMessage());

        APIResponse<Object> response = APIResponse.builder()
                .message("Access denied!")
                .result(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<APIResponse<Object>> handlerNullPointerException(NullPointerException ex) {
        log.warn("NullPointerException: {}", ex.getMessage());

        APIResponse<Object> response = APIResponse.builder()
                .message("Object or data null!")
                .result(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<APIResponse<Object>> handleGenericException(Exception ex) {
        log.error("Unhandled exception:", ex);

        APIResponse<Object> response = APIResponse.builder()
                .message("Internal server error")
                .result(ex.getMessage())
                .build();

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}