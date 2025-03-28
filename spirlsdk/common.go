package spirlsdk

type PageParams struct {
	Token string
	Limit uint32
}

type PageResult struct {
	NextToken string
}
