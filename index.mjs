console.log("MY STATIC SERVER IMPLENTATION");

import got from "got";
import * as crypto from "crypto";
import OAuth from "oauth-1.0a";
import * as qs from "querystring";
import * as env from "dotenv";
import * as rdline from "readline";

env.config({ path: ".env" });

const readLine = rdline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const consumer_key = process.env.CONSUMER_KEY;
const consumer_secret = process.env.CONSUMER_SECRET;

// console.log({ consumer_key, consumer_secret });

// Twitter endpoints for the process to have it signed in
const requestTokenURL =
  "https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write";
const authorizeURL = new URL("https://api.twitter.com/oauth/authorize");
const accessTokenURL = "https://api.twitter.com/oauth/access_token";

const endPointURL = "https://api.twitter.com/2/tweets";

const oauth = OAuth({
  consumer: {
    key: consumer_key,
    secret: consumer_secret,
  },
  signature_method: "HMAC-SHA1",
  hash_function: (baseString, key) =>
    crypto.createHmac("sha1", key).update(baseString).digest("base64"),
});

async function getInput(prompt) {
  return new Promise(async (resolve, reject) => {
    readLine.question(prompt, (out) => {
      readLine.close();
      resolve(out);
    });
  });
}

async function requestAccessToken() {
  const authHeader = oauth.toHeader(
    oauth.authorize({
      url: requestTokenURL,
      method: "POST",
    })
  );

  const result = await got.post(requestTokenURL, {
    headers: {
      Authorization: authHeader["Authorization"],
    },
  });

  if (result.body) {
    return qs.parse(result.body);
  } else {
    throw new Error("OAuth request token call is failed");
  }
}

async function createAccessToken({ oauth_token }, pin) {
  const authHeader = oauth.toHeader(
    oauth.authorize({
      url: accessTokenURL,
      method: "POST",
    })
  );

  const path = `${accessTokenURL}?oauth_verifier=${pin}&oauth_token=${oauth_token}`;
  const result = await got.post(path, {
    headers: {
      Authorization: authHeader["Authorization"],
    },
  });

  if (result.body) {
    return qs.parse(result.body);
  } else {
    throw new Error("OAuth creating access token call is failed");
  }
}

async function tweetFunction(accessToken, message) {
  const token = {
    key: accessToken.oauth_token,
    secret: accessToken.oauth_token_secret,
  };

  const authHeader = oauth.toHeader(
    oauth.authorize(
      {
        url: endPointURL,
        method: "POST",
      },
      token
    )
  );

  const result = await got.post(endPointURL, {
    json: {
      text: message,
    },
    responseType: "json",
    headers: {
      Authorization: authHeader["Authorization"],
      "user-agent": "v2CreateTweetJS",
      "content-type": "application/json",
      accept: "application/json",
    },
  });

  if (result.body) {
    return result.body;
  } else {
    throw new Error("Create Tweet call is failed");
  }
}

async function postTweet(message) {
  try {
    // Get -> request token
    const oAuthRquestToken = await requestAccessToken();
    // Get Authorization
    // will be having a authroization URL, which will get auth for our app on bahalf of us
    authorizeURL.searchParams.append(
      "oauth_token",
      oAuthRquestToken.oauth_token
    );

    // console.log({ authorizeURL });
    console.log(
      `Please visit this website and authorize as it is asking: ${authorizeURL.href}`
    );
    const pin = await getInput(
      "Please enter the PIN which twitter gives to authorize : "
    );
    // will be creating an access token
    const oAuthAccessToken = await createAccessToken(
      oAuthRquestToken,
      pin.trim()
    );
    // console.log({ oAuthAccessToken });
    // will be posting tweets
    const res = await tweetFunction(oAuthAccessToken, message); //twitter api to make tweets

    console.dir(res, { depth: null });
  } catch (err) {
    console.log({ err });
    process.exit(-1);
  }
  process.exit();
}

postTweet(
  "Hello Everyone, I am bot server, tweeting on bahalf of BalajiDuraisamy, please visit www.youtube.com/balajiduraisamy"
);
