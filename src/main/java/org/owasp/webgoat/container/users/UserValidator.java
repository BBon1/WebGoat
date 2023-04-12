package org.owasp.webgoat.container.users;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author nbaars
 * @since 3/19/17.
 */
@Component
@AllArgsConstructor
public class UserValidator implements Validator {

  private final UserRepository userRepository;

  @Override
  public boolean supports(Class<?> clazz) {
    return UserForm.class.equals(clazz);
  }

  @Override
  public void validate(Object o, Errors errors) {
    UserForm userForm = (UserForm) o;

    if (userRepository.findByUsername(userForm.getUsername()) != null) {
      errors.rejectValue("username", "username.duplicate");
    }
      
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();  
    if (!encoder.matches(userForm.getMatchingPassword(), userForm.getPassword())) {
      errors.rejectValue("matchingPassword", "password.diff");
    }
  }
}
