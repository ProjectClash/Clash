package tun

func configureHandedOver(fd int, options Options) error {
	err := configure(fd, options.EXP_RecvMsgX, int(options.MTU))
	if err == nil || !options.EXP_RecvMsgX {
		return err
	}
	if plain := configure(fd, false, int(options.MTU)); plain != nil {
		return err
	}
	if options.Logger != nil {
		options.Logger.Warn("tun: ", err, "; reading the handed-over descriptor without its batch sizing")
	}
	return nil
}
