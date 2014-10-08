# authtokens
authtokens is a [Selenium](http://www.seleniumhq.org/ "selenium")-based tool, written in **Python**, for detecting authentication tokens.

![authtokens.png](authtokens.png "AuthTokens in action")

---

## Usage Example

	python detect_tokens.py -euser@mail.com -uusername -nnickname -ppassword -t0.5 -ihttp://example.com/


## Requirements
* [Firefox](https://www.mozilla.org/ "firefox")
* [PhantomJS](http://www.phantomjs.org/ "phantomjs")


## Dependencies
* Selenium (>= 2.42)
* BeautifulSoup4 (>= 4.3.2)

## License
authtokens is licensed under the [MIT License](http://opensource.org/licenses/MIT).


## References
1. Calzavara, Stefano, et al. "Quite a mess in my cookie jar!: leveraging machine learning to protect web authentication." Proceedings of the 23rd international conference on World wide web. International World Wide Web Conferences Steering Committee, 2014.