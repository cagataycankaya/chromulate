//! Looking profiles up by name, and adding your own.

use std::collections::BTreeMap;
use std::sync::Arc;

use chromulate_core::{Error, Result};

use crate::profile::Profile;

/// A name-to-profile lookup.
///
/// Profiles are shared as `Arc<Profile>` because a client clones one per
/// connection and a `Profile` carries several owned lists.
#[derive(Debug, Clone, Default)]
pub struct ProfileRegistry {
    profiles: BTreeMap<String, Arc<Profile>>,
}

impl ProfileRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiles: BTreeMap::new(),
        }
    }

    /// A registry holding the profiles this crate ships, which today is Chrome
    /// under both `chrome` and `chrome-stable`.
    #[must_use]
    pub fn with_builtin() -> Self {
        let mut registry = Self::new();
        let chrome = Arc::new(Profile::chrome_stable());
        registry
            .profiles
            .insert("chrome".to_owned(), chrome.clone());
        registry.profiles.insert("chrome-stable".to_owned(), chrome);
        registry
    }

    /// Registers a profile under its own name, replacing any previous entry.
    ///
    /// Returns the profile that was displaced, if there was one.
    pub fn register(&mut self, profile: Profile) -> Option<Arc<Profile>> {
        let name = profile.name.to_ascii_lowercase();
        self.profiles.insert(name, Arc::new(profile))
    }

    /// Registers a profile under a name of your choosing.
    pub fn register_as(
        &mut self,
        name: impl Into<String>,
        profile: Profile,
    ) -> Option<Arc<Profile>> {
        self.profiles
            .insert(name.into().to_ascii_lowercase(), Arc::new(profile))
    }

    /// Points a second name at an already registered profile.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the target is not registered.
    pub fn alias(&mut self, alias: impl Into<String>, target: &str) -> Result<()> {
        let profile = self
            .get(target)
            .ok_or_else(|| Error::config(format!("cannot alias unknown profile {target:?}")))?;
        self.profiles
            .insert(alias.into().to_ascii_lowercase(), profile);
        Ok(())
    }

    /// Looks a profile up, case insensitively.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<Profile>> {
        self.profiles.get(&name.to_ascii_lowercase()).cloned()
    }

    /// Looks a profile up, reporting the names on offer when it is missing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when no profile is registered under `name`.
    pub fn require(&self, name: &str) -> Result<Arc<Profile>> {
        self.get(name).ok_or_else(|| {
            Error::config(format!(
                "unknown profile {name:?}; registered profiles are {}",
                self.names().collect::<Vec<_>>().join(", ")
            ))
        })
    }

    /// Removes a profile, returning it.
    pub fn remove(&mut self, name: &str) -> Option<Arc<Profile>> {
        self.profiles.remove(&name.to_ascii_lowercase())
    }

    /// Iterates the registered names in alphabetical order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.profiles.keys().map(String::as_str)
    }

    /// Returns the number of registered names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Returns `true` when nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_registry_offers_chrome_under_both_of_its_names() {
        let registry = ProfileRegistry::with_builtin();
        let names: Vec<&str> = registry.names().collect();

        assert_eq!(names, vec!["chrome", "chrome-stable"]);
        assert_eq!(
            registry.get("chrome").expect("chrome is registered").ja4(),
            registry
                .get("CHROME-Stable")
                .expect("lookup is case insensitive")
                .ja4()
        );
    }

    #[test]
    fn an_unknown_profile_reports_what_is_available() {
        let registry = ProfileRegistry::with_builtin();
        let error = registry
            .require("firefox")
            .expect_err("firefox does not ship with a capture");

        let message = error.to_string();
        assert!(message.contains("firefox"), "{message}");
        assert!(message.contains("chrome"), "{message}");
    }

    #[test]
    fn a_caller_can_register_its_own_profile_and_alias_it() {
        let mut registry = ProfileRegistry::new();
        let mut profile = Profile::chrome_stable();
        profile.name = "chrome-fork".to_owned();

        assert!(registry.register(profile).is_none());
        registry
            .alias("fork", "chrome-fork")
            .expect("aliasing a registered profile succeeds");

        assert!(registry.get("fork").is_some());
        assert_eq!(registry.len(), 2);
        assert!(registry.alias("nope", "missing").is_err());
    }

    #[test]
    fn an_empty_registry_knows_it_is_empty() {
        let mut registry = ProfileRegistry::new();
        assert!(registry.is_empty());

        registry.register_as("x", Profile::chrome_stable());
        assert!(!registry.is_empty());
        assert!(registry.remove("x").is_some());
        assert!(registry.is_empty());
    }
}
