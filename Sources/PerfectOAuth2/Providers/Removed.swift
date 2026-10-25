// Names removed in 2.0.0, kept as unavailable declarations so old call sites get a pointer to the
// replacement instead of "cannot find in scope". See the README's "Migrating to 2.0".


@available(*, unavailable, message: "2.0 removed the global config: pass an OAuth2ClientConfiguration to Google(configuration:restrictedDomain:)")
public enum GoogleConfig {}
@available(*, unavailable, message: "2.0 removed the global config: pass an OAuth2ClientConfiguration to GitHub(configuration:)")
public enum GitHubConfig {}
@available(*, unavailable, message: "2.0 removed the global config: pass an OAuth2ClientConfiguration to Facebook(configuration:)")
public enum FacebookConfig {}
@available(*, unavailable, message: "2.0 removed the global config: pass an OAuth2ClientConfiguration to Slack(configuration:)")
public enum SlackConfig {}
@available(*, unavailable, message: "2.0 removed the global config: pass an OAuth2ClientConfiguration to LinkedIn(configuration:)")
public enum LinkedinConfig {}
@available(*, unavailable, message: "2.0 removed the global config: pass an OAuth2ClientConfiguration to Salesforce(configuration:loginHost:)")
public enum SalesForceConfig {}

@available(*, unavailable, renamed: "LinkedIn")
public typealias Linkedin = LinkedIn
@available(*, unavailable, renamed: "Salesforce")
public typealias SalesForce = Salesforce

@available(*, unavailable, message: "use PendingAuthorization and completeAuthorization(callback:pending:)")
public struct AuthorizationCode {}
@available(*, unavailable, message: "errors are now OAuth2Error cases")
public struct InvalidAPIResponse {}
@available(*, unavailable, message: "errors are now OAuth2Error cases (.network, .timedOut)")
public struct APIConnectionError {}
