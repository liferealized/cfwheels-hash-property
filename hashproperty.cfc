<cfscript>
  component output="false" mixin="model" {

    public HashProperty function init() {
      this.version = "1.1.7,1.1.8,1.4.5,2.0";
      return this;
    }

    /*****************************************
      PUBLIC METHODS
    ******************************************/

    public void function hashProperty(
        string property, string algorithm="PBKDF2WithHMACSHA256"
      , numeric iterationExponent=18, boolean autoUpgrade=true) {

      // normalize our arguments
      if (!StructKeyExists(arguments, "properties"))
        arguments.properties = arguments.property;

      // make sure we have space to save our property info
      if (!structKeyExists(variables.wheels.class, "hashproperties"))
        variables.wheels.class.hashproperties = {};

      // store the hashproperty information into the model so we can access it
      // later on
      for (local.property in listToArray(arguments.properties))
        variables.wheels.class.hashproperties[local.property] = {
            algorithm = arguments.algorithm
          , autoUpgrade = arguments.autoUpgrade
          , iterationExponent = arguments.iterationExponent
        };

      // setup our validation to automatically hash a new password on save
      afterValidation(method="$hashProperties");
    }

    public boolean function checkHash(
      required string property, required string candidate) {

      local.props = duplicate(variables.wheels.class.hashproperties);

      if (!structKeyExists(local.props, arguments.property))
        return false;

      if (!hasProperty(arguments.property))
        return false;

      local.props = local.props[arguments.property];

      local.currentHash = trim(this[arguments.property]);

      // get our iterationExponent, salt and hash from the property
      local.args = {
          iterationExponent = listGetAt(local.currentHash, 1, ":")
        , algorithm = listGetAt(local.currentHash, 2, ":")
        , salt = base64ToHex(listGetAt(local.currentHash, 3, ":"))
      }

      structAppend(local.args, local.props, false);

      local.candidateHash = $hash(
          value = arguments.candidate
        , argumentCollection = local.args
      );

      local.comparison = $slowCompare(local.currentHash, local.candidateHash);

      // if our comparison of the hashes passed and either the current hash's
      // iterationfactor is stale or the algorithm used is stale, upgrade the
      // stored hash to our new settings as long as the developer hasn't turned
      // off auto upgrading when calling hashProperty()
      if (local.comparison
          && local.props.autoUpgrade
          && (local.args.iterationExponent != local.props.iterationExponent
              || local.args.algorithm != local.props.algorithm)) {

        this[arguments.property] = arguments.candidate;

        // save will see that the property storing the password has changed
        // and will rehash it with the new setting automatically
        this.save();
      }

      return local.comparison;
    }

    public any function onMissingMethod(required string missingMethodName, required struct missingMethodArguments) {

      var coreMethod = core.onMissingMethod;

      if (left(arguments.missingMethodName, 5) == "check") {

        local.property = ReplaceNoCase(arguments.missingMethodName, "check", "");

        if (structKeyExists(variables.wheels.class.hashproperties, local.property))
          return checkHash(property=local.property, argumentCollection=arguments.missingMethodArguments);
      }

      return coreMethod(argumentCollection=arguments);
    }

    /*****************************************
      HELPER METHODS
    ******************************************/

    /*
      Helper methos are a direct result of the work by Ben Nadel. Thanks Ben!
      https://www.bennadel.com/blog/2414-converting-data-between-string-binary-hex-and-base64-format-in-coldfusion.htm
     */

   public string function base64ToHex(required string base64Value) {
      local.binaryValue = binaryDecode(arguments.base64Value, "base64");
      return lCase(binaryEncode(local.binaryValue, "hex"));
    }

    public string function hexToBase64(required string hexValue) {
      local.binaryValue = binaryDecode(arguments.hexValue, "hex");
      return binaryEncode(local.binaryValue, "base64");
    }

    public binary function stringToBinary(required string stringValue) {
      local.base64Value = toBase64(arguments.stringValue);
      return toBinary(local.base64Value);
    }

    /*****************************************
      PRIVATE METHODS
    ******************************************/

    /*
      Important method that always compares the two hashes in the same amount
      of time (constant-time algorithm).
     */
    public boolean function $slowCompare(required string a, required string b) {

      // transform our strings to arrays
      local.a = stringToBinary(arguments.a);
      local.b = stringToBinary(arguments.b);

      // xor our array lengths to start with the result
      // if the array lengths are equal, xor is 0
      local.result = bitXor(arrayLen(local.a), arrayLen(local.b));

      for (local.i = 1; local.i lte arrayLen(local.a); local.i++)
        local.result = bitOr(
            local.result
          , bitXor(local.a[local.i], local.b[local.i])
        );

      return (local.result == 0);
    }

    /*
      $hash drops down to java to use the cryptox libraries to use the latest
      standards in password storage as related to the articles below

      https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet
      https://www.owasp.org/index.php/Hashing_Java
      https://nakedsecurity.sophos.com/2013/11/20/serious-security-how-to-store-your-users-passwords-safely/
     */
    public string function $hash(
        required string value, required string algorithm
      , required string iterationExponent, string salt="") {

      // lets generate the salt if it wasn't passed in
      if (!len(arguments.salt))
        for (local.i = 1; local.i lte 2; local.i++)
          arguments.salt &= replace(lCase(createUUID()), "-", "", "all");

      // get the secret key factory to create our hash
      local.skf = createObject("java", "javax.crypto.SecretKeyFactory")
        .getInstance(javaCast("string", arguments.algorithm));

      // run our pbekeyspec with our iterationExponent to slow down
      // offline attacks
      local.spec = createObject("java", "javax.crypto.spec.PBEKeySpec")
        .init(
            javaCast("char[]", listToArray(arguments.value, ""))
          , javaCast("char[]", listToArray(arguments.salt, ""))
          , javaCast("int", 2 ^ arguments.iterationExponent)
          , javacast("int", right(arguments.algorithm, 3))
        );

      // get our final hash
      local.key = local.skf.generateSecret(local.spec);

      // we store our iterationExponent, algo used, salt and the hash
      // together as one string in the db seperated by colons so that the
      // developer can upgrade the encryption or iternation exponent used
      // without having an adverse effect on overall functionality.
      // This also allows the plugin to seamlessly upgrade the user to the
      // new hashing algo/exponent should the developer change them
      local.result = [
          arguments.iterationExponent
        , arguments.algorithm
        , hexToBase64(arguments.salt)
        , binaryEncode(local.key.getEncoded(), "base64")
      ];

      return arrayToList(local.result, ":");
    }

    public void function $hashProperties() {

      local.properties = variables.wheels.class.hashProperties;

      for (local.property in local.properties) {
        if (hasChanged(local.property) and structKeyExists(this, local.property)) {
          this[local.property] = $hash(
              value = this[local.property]
            , argumentCollection = local.properties[local.property]
          );
        }
      }
    }
  }
</cfscript>
